package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gitlab.inlabs.app/cyber/insiderci"
)

var (
	version string
)

const (
	usageText = `
insiderci is a utility that can be used on CI mats to perform tests on the Insider platform.

`
)

var (
	emailFlag     = flag.String("email", "", "Insider email")
	passwordFlag  = flag.String("password", "", "Insider password")
	noFailFlag    = flag.Bool("no-fail", false, "Do not fail analysis, even if issues were found")
	scoreFlag     = flag.Int("score", 0, "Score to fail pipeline")
	componentFlag = flag.Int("component", 0, "Component ID")
	saveFlag      = flag.Bool("save", false, "Save results on file in json and html format")
	versionFlag   = flag.Bool("version", false, "Print version")
	Tech          = flag.String("tech", "", "Setting a technologies")
)

func usage() {
	fmt.Fprintf(os.Stderr, usageText)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	os.Exit(run(flag.Args(), os.Stderr))
}

func run(args []string, out io.Writer) int {
	if *versionFlag {
		fmt.Fprintf(out, "insiderci version %s", version)
		return 0
	}

	// check if Tech is chosen
	if *componentFlag == 0 {
		if *Tech == "" {
			flag.Usage()
			return 1
		} else {
			// autenticate the user
			token, err := insiderci.Autenticate(*emailFlag, *passwordFlag)
			if err != nil {
				fmt.Println(err.Error())
				return 1
			}
			// get all Available technologies
			techlist, err := insiderci.GetTech(token)
			if err != nil {
				fmt.Println(err.Error())
				return 1
			}
			// seek for the tecnology inserted and get the id
			tech_id, err := insiderci.ChooseTech(techlist, *Tech)
			if err != nil {
				fmt.Println(err.Error())
				return 1
			}
			if *componentFlag == 0 {
				path, _ := os.Getwd()
				split := strings.Split(path, "/")
				name := split[len(split)-2] + "-" + split[len(split)-1]
				log.Println("Component name created automatically:", name)
				*componentFlag, err = insiderci.GetComponet(token, name, tech_id)
				if err != nil {
					fmt.Println(err.Error())
					return 1
				}
			}
		}
	}

	if len(args) < 1 {
		flag.Usage()
		return 1
	}

	filename := args[0]

	insider, err := insiderci.New(*emailFlag, *passwordFlag, filename, *componentFlag)
	if err != nil {
		fmt.Fprintf(out, "Error: %v\n", err)
		return 1
	}

	sast, err := insider.Start()
	if err != nil {
		fmt.Fprintf(out, "Error: %v\n", err)
		return 1
	}

	resumeSast(os.Stdout, sast)

	if *saveFlag {
		if err := saveSast(*componentFlag, sast); err != nil {
			fmt.Fprintf(out, "Error to save results: %v\n", err)
			return 1
		}
	}

	if !*noFailFlag {
		if len(sast.SastVulnerabilities) > 0 {
			if *scoreFlag == 0 {
				return 1
			}
			if *scoreFlag >= sast.SecurityScore {
				fmt.Fprintf(out, "Score %d lower than %d\n", sast.SecurityScore, *scoreFlag)
				return 1
			}
		}
	}
	return 0
}

func zipDir(dir string) (string, error) {
	zipOut, err := os.OpenFile(fmt.Sprintf("%s.zip", dir), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return "", err
	}
	defer zipOut.Close()

	writer := zip.NewWriter(zipOut)
	defer writer.Close()

	err = filepath.Walk(dir, func(file string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		f, err := os.Open(file)
		if err != nil {
			return err
		}
		path, err := filepath.Rel(dir, file)
		if err != nil {
			return err
		}
		z, err := writer.Create(path)
		if err != nil {
			return err
		}

		if _, err := io.Copy(z, f); err != nil {
			return err
		}
		return nil
	})
	return zipOut.Name(), err
}

func saveSast(component int, sast *insiderci.Sast) error {
	b, err := json.MarshalIndent(sast, "", "\t")
	if err != nil {
		return err
	}
	file, err := os.Create(fmt.Sprintf("result-%d.json", component))
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(b); err != nil {
		return err
	}
	return saveSastHtml(component, sast)
}

func saveSastHtml(component int, sast *insiderci.Sast) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}
	file, err := os.Create(fmt.Sprintf("result-%d.html", component))
	if err != nil {
		return err
	}
	defer file.Close()
	if err := tmpl.Execute(file, sast); err != nil {
		return err
	}
	resp, err := http.Get("https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create("style.css")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func resumeSast(out io.Writer, sast *insiderci.Sast) {
	fmt.Fprintln(out, "-----------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, "Score Security %v/100\n", sast.SecurityScore)
	fmt.Fprintln(out, "-----------------------------------------------------------------------------------------------------------------------")
	if len(sast.SastDras) > 0 {
		fmt.Fprintf(out, "DRA - Data Risk Analytics\n")
		for _, dra := range sast.SastDras[0:] {
			fmt.Fprintf(out, "File: %s\n", dra.File)
			fmt.Fprintf(out, "Dra: %s\n", dra.Dra)
			fmt.Fprintf(out, "Type: %s\n", dra.Type)
		}
	}

	if len(sast.SastVulnerabilities) > 0 {
		fmt.Fprintln(out, "-----------------------------------------------------------------------------------------------------------------------")
		fmt.Fprintf(out, "Vulnerabilities\n")
		for _, v := range sast.SastVulnerabilities[0:] {
			fmt.Fprintf(out, "CVSS: %s\n", v.Cvss)
			fmt.Fprintf(out, "Rank: %s\n", v.Rank)
			fmt.Fprintf(out, "Class: %s\n", v.Class)
			fmt.Fprintf(out, "Method: %s\n", v.Method)
			fmt.Fprintf(out, "VulnerabilityID: %s\n", v.VulID)
			fmt.Fprintf(out, "LongMessage: %s\n", v.LongMessage)
			fmt.Fprintf(out, "ClassMessage: %s\n", v.ClassMessage)
			fmt.Fprintf(out, "ShortMessage: %s\n\n", v.ShortMessage)
		}
	}

	fmt.Fprintln(out, "-----------------------------------------------------------------------------------------------------------------------")
}
