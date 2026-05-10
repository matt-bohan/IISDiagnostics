function Format-NumberedLines {
    param([string[]]$Items)

    if ($null -eq $Items -or $Items.Count -eq 0) {
        return ''
    }

    ($Items | ForEach-Object -Begin { $n = 1 } -Process { '{0}. {1}' -f $n++, $_ }) -join [Environment]::NewLine
}
function Format-NumberedLines {
    param([string[]]$Items)
    if ($null -eq $Items -or $Items.Count -eq 0) {
        return ''
    }
    ($Items | ForEach-Object -Begin { $n = 1 } -Process { '{0}. {1}' -f $n++, $_ }) -join [Environment]::NewLine
}