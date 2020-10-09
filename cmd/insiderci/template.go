package main

const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1, shrink-to-fit=no"
    />
    <title>Report</title>
    <link href="./style.css" rel="stylesheet" />
    <link
      href="https://fonts.googleapis.com/css2?family=Inconsolata:wght@300&display=swap"
      rel="stylesheet"
    />
  </head>
  <style>
    body {
      font-family: "Inconsolata", monospace;
      font-size: 13px;
    }
  </style>
  <body>
    <div class="container" style="border: rgba(0, 0, 0, 0.1) 1px solid;">
      <div class="row">
        <div class="col-4">
          <img
            src="https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png"
            alt=""
            class="img-fluid"
            style="margin-bottom: 20px;"
          />
        </div>
      </div>
      <div class="row">
        <div class="col-12">
          <h6>Score Security {{ .SastResult.SecurityScore }}/100</h6>
        </div>
        <hr />
      </div>
      <hr />
      <div class="row">
      </div>
      <hr />
      <hr />
      <div class="row">
        <div class="col-12">
          <h6>DRA - Data Risk Analytics</h6>
          <div class="table-responsive">
            <table class="table table-sm">
              <tbody>
                {{ range .SastDras }}
                <tr>
                  <td class="user-select-all">
                    <b>File :</b>{{ .File}}<br />
                    <b>Dra :</b>{{ .Dra}}<br />
                    <b>Type :</b>{{ .Type}}
                  </td>
                </tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {{ if .SastLibraries }}
      <div class="row">
        <div class="col-12">
          <h6>Libraries</h6>
          <div class="table-responsive">
            <table class="table table-sm">
              <thead>
                <tr>
                  <td>Name</td>
                  <td>Version</td>
                </tr>
              </thead>
              <tbody>
                {{ range .SastLibraries }}
                <tr class="user-select-all">
                  <td>{{ .Name}}</td>
                  <td>{{ .Version}}</td>
                </tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {{ end }}
      {{ if .SastVulnerabilities }}
      <div class="row">
        <div class="col-12">
          <h6>Vulnerabilities</h6>
          <div class="">
            <table class="table table-sm" style="table-layout: fixed;">
              <tbody>
                {{ range .SastVulnerabilities }}
                <tr>
                  <td class="user-select-all">
                    <p class="text-break">
                      <b>CVSS :</b>{{ .Cvss }}<br />
                      <b>Rank :</b>{{ .Rank}}<br />
                      <b>Class :</b>{{ .Class}}<br />
                      <b>VulnerabilityID :</b>{{ .VulID}}<br />
                      <b>Method :</b>{{ .Method}}<br />
                      <b>LongMessage :</b>{{ .LongMessage}}<br />
                      <b>ClassMessage :</b>{{ .ClassMessage}}<br />
                      <b>ShortMessage :</b>{{ .ShortMessage}}<br />
                    </p>
                  </td>
                </tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {{ end }}
      <div
        class="row"
        style="border-top: #dee2e6 1px solid; padding-top: 10px;"
      >
      </div>
    </div>
  </body>
</html>


`
