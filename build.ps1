Get-Process -Name 'AppContainer' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
$env:VCTargetsPath = 'D:\app-install\CodingTools\VisualStudio\Installer\MSBuild\Microsoft\VC\v170\'
& 'D:\app-install\CodingTools\VisualStudio\Installer\MSBuild\Current\Bin\amd64\MSBuild.exe' 'F:\Project\git\appcontainer\AppContainer\AppContainer.sln' /p:Configuration=Release /p:Platform=x64 /v:minimal
