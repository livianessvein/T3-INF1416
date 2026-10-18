@echo off
REM Compila o Cofre Digital e o logView e gera os dois JARs executaveis (Windows).
setlocal
cd /d "%~dp0"

set CP=lib\bcprov-jdk18on-1.77.jar;lib\sqlite-jdbc-3.46.1.3.jar
if exist out rmdir /s /q out
if exist dist\lib rmdir /s /q dist\lib
if exist dist\*.jar del /q dist\*.jar
mkdir out
if not exist dist mkdir dist

dir /s /b src\*.java > out\sources.txt
javac --release 17 -encoding UTF-8 -d out -cp "%CP%" @out\sources.txt || exit /b 1

set MCP=lib/bcprov-jdk18on-1.77.jar lib/sqlite-jdbc-3.46.1.3.jar

(echo Main-Class: cofre.CofreDigital& echo Class-Path: %MCP%& echo Enable-Native-Access: ALL-UNNAMED) > out\cofre.mf
jar cfm dist\CofreDigital.jar out\cofre.mf -C out cofre || exit /b 1

(echo Main-Class: logview.LogView& echo Class-Path: %MCP%& echo Enable-Native-Access: ALL-UNNAMED) > out\logview.mf
pushd out
jar cfm ..\dist\LogView.jar logview.mf logview cofre\CryptoUtil.class "cofre\CryptoUtil$KeyValidationException.class" "cofre\CryptoUtil$KeyValidationException$Motivo.class" || (popd & exit /b 1)
popd

if not exist dist\lib mkdir dist\lib
copy /y lib\*.jar dist\lib\ > nul

echo Gerados: dist\CofreDigital.jar e dist\LogView.jar
echo Executar:  cd dist ^&^& java -jar CofreDigital.jar
echo Auditoria: cd dist ^&^& java -jar LogView.jar ^<caminho_chave_privada_admin^>
endlocal
