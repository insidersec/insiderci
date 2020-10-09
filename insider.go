package insiderci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

var (
	SastURL   = ""
	UploadURL = ""
)

type sastError struct {
	Message string `json:"message"`
}

type Sast struct {
	ID         int    `json:"id"`
	Log        string `json:"log"`
	Status     int    `json:"status"`
	SastResult struct {
		ID            int    `json:"id"`
		AverageCvss   string `json:"averageCvss"`
		SecurityScore string `json:"securityScore"`
		NumberOfLines int    `json:"numberOfLines"`
		Size          string `json:"size"`
		Md5           string `json:"md5"`
		Sha1          string `json:"sha1"`
		Sha256        string `json:"sha256"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Sast          int    `json:"sast"`
	} `json:"SastResult"`
	SastVulnerabilities []struct {
		ID            int      `json:"id"`
		Cwe           string   `json:"cwe"`
		Cvss          string   `json:"cvss"`
		Rank          string   `json:"rank"`
		Priority      string   `json:"priority"`
		Category      string   `json:"category"`
		ShortMessage  string   `json:"shortMessage"`
		LongMessage   string   `json:"longMessage"`
		Class         string   `json:"class"`
		ClassMessage  string   `json:"classMessage"`
		Method        string   `json:"method"`
		MethodMessage string   `json:"methodMessage"`
		Line          int      `json:"line"`
		Column        int      `json:"column"`
		Status        bool     `json:"status"`
		Analyse       bool     `json:"analyse"`
		VulID         string   `json:"vul_id"`
		AffectedFiles []string `json:"affectedFiles"`
	} `json:"SastVulnerabilities"`
	SastScas []struct {
		CWE           string `json:"cwe"`
		CVEs          string `json:"cves"`
		Title         string `json:"title"`
		Severity      string `json:"severity"`
		ID            int    `json:"advisoryId"`
		Description   string `json:"description"`
		Recomendation string `json:"recomendation"`
	} `json:"SastScas"`
	SastLibraries []struct {
		Name                 string `json:"name"`
		Version              string `json:"current"`
		Source               string `json:"source"`
		CompatibilityVersion string `json:"compatiblityVersion"`
	} `json:"SastLibraries"`
	SastDras []struct {
		Dra  string `json:"dra"`
		File string `json:"file"`
		ID   int    `json:"id"`
		Type string `json:"type"`
	} `json:"SastDras"`
}

type sastExecution struct {
	SastCreated Sast `json:"sastCreated"`
}

type component struct {
	ID     int    `json:"id"`
	Status int    `json:"status"`
	Sasts  []Sast `json:"Sasts"`
}

type Insider struct {
	logger    *log.Logger
	token     string
	filename  string
	component int
}

func New(email, password, filename string, component int) (*Insider, error) {
	token, err := auhenticate(email, password)
	if err != nil {
		return nil, err
	}
	return &Insider{
		logger:    log.New(os.Stderr, "", log.LstdFlags),
		token:     token,
		filename:  filename,
		component: component,
	}, nil
}

func (i *Insider) Start() (*Sast, error) {
	sast, err := i.startAnalysis()
	if err != nil {
		return nil, err
	}
	sast, err = i.watchAnalysis(sast)
	if err != nil {
		return nil, err
	}
	if sast.Status != 2 {
		return nil, fmt.Errorf(sast.Log)
	}
	i.logger.Println("Analysis finish with successfull")
	return &sast, nil
}

func (i *Insider) watchAnalysis(s Sast) (Sast, error) {
	i.logger.Println("Waiting to finish analysis")
	req, err := i.request(http.MethodGet, fmt.Sprintf("%s/api/sast/%d/component/%d", SastURL, s.ID, i.component), nil)
	if err != nil {
		return Sast{}, err
	}
	for {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return Sast{}, err
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return Sast{}, err
		}

		var res Sast
		if err := json.Unmarshal(b, &res); err != nil {
			return Sast{}, err
		}

		if res.Status != 1 {
			return res, nil
		}

		if err := resp.Body.Close(); err != nil {
			return Sast{}, err
		}

		time.Sleep(1 * time.Second)
	}
}

func (i *Insider) startAnalysis() (Sast, error) {
	i.logger.Println("Starting analysis")
	file, err := os.Open(i.filename)
	if err != nil {
		return Sast{}, err
	}
	defer file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("package", file.Name())
	if err != nil {
		return Sast{}, err
	}

	if _, err := io.Copy(part, file); err != nil {
		return Sast{}, err
	}
	if err := writer.Close(); err != nil {
		return Sast{}, err
	}

	req, err := i.request(http.MethodPost, fmt.Sprintf("%s/core/api/v1/sast/%d", UploadURL, i.component), body)
	if err != nil {
		return Sast{}, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Sast{}, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Sast{}, err
	}

	if resp.StatusCode != http.StatusOK {
		var sastErr sastError
		if err := json.Unmarshal(b, &sastErr); err != nil {
			return Sast{}, fmt.Errorf("unexpected error response: %s", string(b))
		}
		if len(sastErr.Message) == 0 {
			return Sast{}, fmt.Errorf("unexpected error response: %s", string(b))
		}
		return Sast{}, fmt.Errorf(sastErr.Message)
	}

	var s sastExecution
	if err := json.Unmarshal(b, &s); err != nil {
		return Sast{}, fmt.Errorf("unexpected success response: %v", err)
	}

	return s.SastCreated, nil
}

func (i *Insider) request(method, url string, body io.Reader) (*http.Request, error) {
	// TODO add timeout
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", i.token)
	return req, nil
}

func auhenticate(email, password string) (string, error) {
	data := map[string]string{
		"email":    email,
		"password": password,
	}

	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/auth", SastURL), bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := make(map[string]interface{})
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	token, ok := response["token"]
	if !ok {
		return "", fmt.Errorf("not found token in response: %s", string(body))
	}

	return token.(string), nil
}
