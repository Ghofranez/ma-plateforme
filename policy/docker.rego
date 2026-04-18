package security.docker

deny[msg] {
    input.Instructions[_].Cmd == "USER"
    input.Instructions[_].Value == "root"
    msg = "Le conteneur ne doit pas tourner en root"
}