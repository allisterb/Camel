@echo off
pushd
@setlocal
set ERROR_CODE=0

src\Camel.CLI\bin\Debug\net9.0\Camel.CLI.exe %*

:end
@endlocal
popd
exit /B %ERROR_CODE%