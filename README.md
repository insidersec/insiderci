# InsiderCI
Insider CI é um utilitário que pode ser utilizado em todas esteiras de CI para realizar execuções na plataforma [Insider](https://insidersec.io/).

## Download
Você encontra binários pré compilados para Linux, Windows e Mac [aqui](https://github.com/insidersec/insiderci/releases/latest).

## Utilizando InsiderCI
### Help
```bash
insiderci -h

insiderci is a utility that can be used on CI mats to perform tests on the Insider platform.

  -component int
        Component ID
  -email string
        Insider email
  -no-fail
        Do not fail analysis, even if issues were found
  -password string
        Insider password
  -save
        Save results on file in json and html format
  -score float
        Score to fail pipeline
  -version
        Print version
```
### Executando

```sh
$ wget https://github.com/insidersec/insiderci/releases/download/v0.3.0/insiderci_0.3.0_linux_x86_64.tar.gz -q 
$ tar -xf insiderci_0.3.0_linux_x86_64.tar.gz
$ chmod +x ./insiderci
$ ./insiderci -email "USUARIO" -password "SENHA" -score "SCORE" -component "ID_COMPONENTE"  "ARQUIVO"
```
USUÁRIO: Usuário do Insider.
SENHA: Senha do Insider.
SCORE: Score mínimo de segurança que é valido para prosseguir a pipeline.
ID_COMPONENTE: ID do componente no Insider.
ARQUIVO: Nome do arquivo que deve ser analisado.

#### Exemplo de execução
```sh
$ ./insiderci -email 'insider@insider.com' -password 'senha123' -score 80 -component 1 'build.zip'
```
Para iniciar a analise é necessário ter acesso a plataforma do Insider, um componente criado e um arquivo zip/apk/ipa pronto para analise. O InsiderCI vai esperar até a analise ser finaliza, e após isso, caso alguma vulnerabilidade seja encontrada, será finalizado com erro.
