# insiderci
Insider CI é um utilitário que pode ser utilizado nas esteiras de CI para realizar testes na plataforma do Insider.


## Download
TODO

## Utilização
Help
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

Para iniciar a analise é necessário ter acesso a plataforma do Insider, um componente criado e um arquivo zip/apk/ipa pronto para analise. O Insider CI vai esperar até a analise ser finaliza, e após isso, caso alguma vulnerabilidade seja encontrada, será finalizado com erro.
```bash
insiderci -email $INSIDER_EMAIL -password $INSIDER_PASSWORD -compoenet 1 arquivo_zip.zip
```
