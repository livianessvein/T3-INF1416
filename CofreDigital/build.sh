#!/bin/sh
# Compila o Cofre Digital e o logView e gera os dois JARs executáveis.
set -e
cd "$(dirname "$0")"

CP="lib/bcprov-jdk18on-1.77.jar:lib/sqlite-jdbc-3.46.1.3.jar"
rm -rf out dist/lib dist/*.jar   # preserva dist/cofre.db
mkdir -p out dist

javac --release 17 -encoding UTF-8 -d out -cp "$CP" $(find src -name "*.java")

MANIFEST_CP="lib/bcprov-jdk18on-1.77.jar lib/sqlite-jdbc-3.46.1.3.jar"

# Cofre Digital: apenas o pacote cofre (sem o logView)
printf "Main-Class: cofre.CofreDigital\nClass-Path: %s\nEnable-Native-Access: ALL-UNNAMED\n" "$MANIFEST_CP" > out/cofre.mf
jar cfm dist/CofreDigital.jar out/cofre.mf -C out cofre

# logView: programa separado; leva apenas a classe de apoio CryptoUtil
printf "Main-Class: logview.LogView\nClass-Path: %s\nEnable-Native-Access: ALL-UNNAMED\n" "$MANIFEST_CP" > out/logview.mf
(cd out && jar cfm ../dist/LogView.jar logview.mf logview cofre/CryptoUtil.class 'cofre/CryptoUtil$KeyValidationException.class' 'cofre/CryptoUtil$KeyValidationException$Motivo.class')

mkdir -p dist/lib
cp lib/*.jar dist/lib/

echo "Gerados: dist/CofreDigital.jar e dist/LogView.jar"
echo "Executar:  cd dist && java -jar CofreDigital.jar"
echo "Auditoria: cd dist && java -jar LogView.jar <caminho_chave_privada_admin>"
