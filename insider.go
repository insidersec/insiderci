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
	"strings"
	"time"
)

var (
	UploadURL = "https://upload.insidersec.io/core/api/v1"
	SastURL   = "https://backend.insidersec.io/core/api/v1"
)

type sastError struct {
	Message string `json:"message"`
}

type ListTech []struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	Technology       string    `json:"technology"`
	FormatPermission string    `json:"formatPermission"`
	Description      string    `json:"description"`
	Enabled          bool      `json:"enabled"`
	Jenkins          bool      `json:"jenkins"`
	TemplateJenkins  string    `json:"templateJenkins"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ComponentPost struct {
	Name string `json:"name"`
	Tech int    `json:"technology"`
}

type ComponentReceive struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
}

type Sast struct {
	ID                  int    `json:"id"`
	Log                 string `json:"log"`
	Status              int    `json:"status"`
	SecurityScore       int    `json:"securityScore"`
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
	} `json:"vulnerabilities"`
	SastDras []struct {
		Dra  string `json:"dra"`
		File string `json:"file"`
		ID   int    `json:"id"`
		Type string `json:"type"`
	} `json:"dra"`
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

func Authenticate(email, password string) (string, error) {
	token, err := authenticate(email, password)
	if err != nil {
		return "", fmt.Errorf("authenticate %w", err)
	}
	return token, nil
}

func New(email, password, filename string, component int) (*Insider, error) {
	token, err := authenticate(email, password)
	if err != nil {
		return nil, fmt.Errorf("authenticate %w", err)
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
		return nil, fmt.Errorf("start analysis %w", err)
	}
	sast, err = i.watchAnalysis(sast)
	if err != nil {
		return nil, fmt.Errorf("watch analysis %w", err)
	}
	if sast.Status != 2 {
		return nil, fmt.Errorf(sast.Log)
	}
	i.logger.Println("Analysis finish with successfull")
	return &sast, nil
}

func (i *Insider) watchAnalysis(s Sast) (Sast, error) {
	i.logger.Println("Waiting to finish analysis")
	req, err := i.request(http.MethodGet, fmt.Sprintf("%s/sast/%d/component/%d/ci", SastURL, s.ID, i.component), nil)
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

		if resp.StatusCode != http.StatusOK {
			return Sast{}, fmt.Errorf("status code %d: %s", resp.StatusCode, string(b))
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

	req, err := i.request(http.MethodPost, fmt.Sprintf("%s/sast/%d", UploadURL, i.component), body)
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

	// var s sastExecution
	// if err := json.Unmarshal(b, &s); err != nil {
	// 	return Sast{}, fmt.Errorf("unexpected success response: %v", err)
	// }

	// API has changed 
	// now it can returns a map of file parts that has been uploaded 
	// 
	// to perform CI (continous integration) we consider just the first element 
	// returned by the API as the COMPONENT the be watched during the next cycles
	// 
	// this works since CI only uploads one file per time ... 
	// 
	var dat map[string]interface{}
	if err := json.Unmarshal(b, &dat); err != nil { 
        Sast{}, fmt.Errorf("unexpected success response: %v", err)
    }

    uploadedFiles := reflect.ValueOf(dat).MapKeys()

    // we only look for ID of the COMPONENT returned by the API ... 

	var sx Sast
	sx.ID, _ = strconv.Atoi(dat[keys[0].Interface().(string)].(map[string]interface{})["ID"].(string))

	fmt.Println("returned value => %v", sx)

	return sx, nil 
	// return s.SastCreated, nil
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

func authenticate(email, password string) (string, error) {
	data := map[string]string{
		"email":    email,
		"password": password,
	}

	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/auth", SastURL), bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %d\n%s", resp.StatusCode, string(body))
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

func GetTech(token string) (ListTech, error) {
	var res ListTech
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%v/technologies", SastURL), nil)
	if err != nil {
		return res, fmt.Errorf(err.Error())
	}
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, fmt.Errorf(err.Error())
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return res, fmt.Errorf(err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("status code %d: %s \n", resp.StatusCode, string(b))
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return res, fmt.Errorf(err.Error())
	}

	return res, nil
}

func ChooseTech(techlist ListTech, tech string) (int, error) {
	for _, v := range techlist {
		if strings.ToLower(tech) == strings.ToLower(v.Name) {
			return v.ID, nil
		}
	}
	fmt.Printf("\nAvailable technologies, please choose one. \n\n")
	for _, v := range techlist {
		//fmt.Println(strings.ToLower(strings.ReplaceAll(v.Name, " ", "_")))
		fmt.Println(v.Name)
	}
	fmt.Println("\nUsage:")
	fmt.Printf("./insiderci -email \"<user-email>\" -password  \"<password>\" -score 80 -tech \"%v\"  \"<file-name>\" \n", techlist[1].Name)
	return 0, fmt.Errorf(" ")
}

func GetComponet(token, name string, tech int) (int, error) {
	post := ComponentPost{
		Name: name,
		Tech: tech,
	}
	b, err := json.Marshal(post)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%v/component/ci", SastURL), bytes.NewBuffer(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status code:aquiii  %d\n%s", resp.StatusCode, string(body))
	}

	var ret ComponentReceive

	if err := json.Unmarshal(body, &ret); err != nil {
		return 0, err
	}

	return ret.ID, nil
}
