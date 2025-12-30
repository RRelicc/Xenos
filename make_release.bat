@echo off

if "%~1"=="" (
	echo Release version must be specified as an argument
	goto quit
)

set ver=%1
set zipper="C:\Program Files\7-Zip\7z.exe"

if not exist Releases mkdir Releases
if not exist Releases\Pdb mkdir Releases\Pdb

mkdir %ver%

cd %ver%
copy ..\build\Win32\Release\Xenos.exe Xenos.exe
copy ..\build\x64\Release\Xenos64.exe Xenos64.exe
if exist ..\Releases\Changelog.txt copy ..\Releases\Changelog.txt Changelog.txt
if exist ..\Releases\Readme.txt copy ..\Releases\Readme.txt Readme.txt
if exist ..\README.md copy ..\README.md README.md
%zipper% a -t7z Xenos_%ver%.7z * -mx=9 -myx=9
copy Xenos_%ver%.7z ..\Releases\Xenos_%ver%.7z
cd ..
rmdir /S /Q %ver%

if not exist Releases\Pdb\%ver% mkdir Releases\Pdb\%ver%
copy  build\Win32\Release\Xenos.pdb Releases\Pdb\%ver%\Xenos.pdb
copy  build\x64\Release\Xenos64.pdb Releases\Pdb\%ver%\Xenos64.pdb

:quit