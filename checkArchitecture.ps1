$path = "C:\Users\meiso\Desktop\bachelors\Fragmentator\cryptor\CryptorAttempt2\payload.exe"
if (!(Test-Path $path)) {
    Write-Error "File not found: $path"
    return
}
$fs = [System.IO.File]::OpenRead($path)
$br = New-Object System.IO.BinaryReader $fs
$fs.Position = 0x3C
$peOffset = $br.ReadInt32()
$fs.Position = $peOffset + 4
$machine = $br.ReadUInt16()
$br.Close()
$fs.Close()

switch ($machine) {
    0x8664 { "64-bit (x64)" }
    0x14C  { "32-bit (x86)" }
    default { "Unknown architecture: 0x$('{0:X}' -f $machine)" }
}
