@echo off
echo Building Camel...
dotnet restore src\Camel.sln
dotnet build src\Camel.CLI\Camel.CLI.csproj /p:Configuration=Debug