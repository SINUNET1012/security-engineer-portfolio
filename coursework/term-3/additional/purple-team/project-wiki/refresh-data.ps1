$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$wikiDir = Join-Path $root "project-wiki"

$fileItems = Get-ChildItem -Path $root -Recurse -File | Where-Object {
  $_.FullName -notmatch [regex]::Escape($wikiDir)
}

$files = $fileItems | ForEach-Object {
  $rel = $_.FullName.Substring($root.Length + 1) -replace "\\", "/"
  $top = ($rel -split "/")[0]
  $ext = if ([string]::IsNullOrWhiteSpace($_.Extension)) { "(none)" } else { $_.Extension.ToLower() }

  [PSCustomObject]@{
    path = $rel
    topFolder = $top
    ext = $ext
    sizeBytes = [int64]$_.Length
    sizeMB = [Math]::Round($_.Length / 1MB, 3)
    modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
  }
}

$links = Get-ChildItem -Path $root -Recurse -File -Include *.url | Where-Object {
  $_.FullName -notmatch [regex]::Escape($wikiDir)
} | ForEach-Object {
  $rel = $_.FullName.Substring($root.Length + 1) -replace "\\", "/"
  $line = Get-Content -LiteralPath $_.FullName | Where-Object { $_ -like "URL=*" } | Select-Object -First 1

  [PSCustomObject]@{
    title = $_.BaseName
    path = $rel
    url = ($line -replace "^URL=", "")
  }
}

$byTop = $files | Group-Object topFolder | ForEach-Object {
  [PSCustomObject]@{
    topFolder = $_.Name
    fileCount = $_.Count
    totalSizeMB = [Math]::Round((($_.Group | Measure-Object -Property sizeBytes -Sum).Sum) / 1MB, 3)
  }
} | Sort-Object topFolder

$byExt = $files | Group-Object ext | ForEach-Object {
  [PSCustomObject]@{
    ext = $_.Name
    count = $_.Count
  }
} | Sort-Object count -Descending

$data = [PSCustomObject]@{
  generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  root = $root
  summary = [PSCustomObject]@{
    totalFiles = $files.Count
    totalSizeMB = [Math]::Round((($files | Measure-Object -Property sizeBytes -Sum).Sum) / 1MB, 3)
    byTopFolder = $byTop
    byExtension = $byExt
  }
  files = $files | Sort-Object path
  links = $links | Sort-Object path
}

$json = $data | ConvertTo-Json -Depth 8
$js = "window.WIKI_DATA = $json;"
$target = Join-Path $PSScriptRoot "wiki-data.js"
Set-Content -Path $target -Value $js -Encoding UTF8

Write-Host "Updated: $target"
