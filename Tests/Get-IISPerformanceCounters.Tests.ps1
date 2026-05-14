Describe 'Get-IISPerformanceCounters' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns a snapshot with graded measures from mocked counters' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}

            Mock Get-Counter {
                param(
                    [string[]]$Counter,
                    [string]$ListSet,
                    [int]$SampleInterval,
                    [int]$MaxSamples
                )

                if ($ListSet) {
                    switch ($ListSet) {
                        'HTTP Service Request Queues' {
                            return [pscustomobject]@{
                                CounterSetName = $ListSet
                                Counter        = @('\HTTP Service Request Queues(*)\CurrentQueueSize')
                            }
                        }
                        'APP_POOL_WAS' {
                            return [pscustomobject]@{
                                CounterSetName = $ListSet
                                Counter        = @('\APP_POOL_WAS(*)\Current Application Pool State')
                            }
                        }
                        default {
                            return [pscustomobject]@{
                                CounterSetName = $ListSet
                                Counter        = @()
                            }
                        }
                    }
                }

                $samples = @()
                foreach ($path in $Counter) {
                    $value = switch -Wildcard ($path) {
                        '*CurrentQueueSize*' { 40 }
                        '*Current Application Pool State*' { 3 }
                        default { 0 }
                    }
                    $samples += [pscustomobject]@{
                        Path        = $path.Replace('(*)', '(DefaultAppPool)')
                        CookedValue = $value
                    }
                }

                return [pscustomobject]@{
                    CounterSamples = $samples
                }
            }

            $result = Get-IISPerformanceCounters -AppPoolName 'DefaultAppPool'

            if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.PerformanceCounterSnapshot') {
                throw "Expected IISDiagnostics.PerformanceCounterSnapshot, got '$($result.PSObject.TypeNames[0])'."
            }

            $queueMeasure = $result.Measures | Where-Object { $_.Name -eq 'Current queue size' } | Select-Object -First 1
            if (-not $queueMeasure) {
                throw 'Expected a Current queue size measure.'
            }
            if ($queueMeasure.Severity -ne 'Critical') {
                throw "Expected queue severity Critical for mocked value 40, got '$($queueMeasure.Severity)'."
            }
            if ($result.Findings.Count -lt 1) {
                throw 'Expected at least one performance finding for non-OK measures.'
            }
        }
    }

    It 'does not duplicate WhatToExpect text in Info finding detail' {
        InModuleScope IISDiagnostics {
            $measure = New-IISPerformanceMeasure `
                -Category 'SqlClient' `
                -Name 'Pooled SQL connections' `
                -Severity 'Info' `
                -FormattedValue '12' `
                -WhatToExpect 'Pool size is informational.' `
                -OkGuidance 'Current pool size is healthy.' `
                -WarningGuidance 'Pool size warning.' `
                -CriticalGuidance 'Pool size critical.'

            if ($measure.StatusSummary -ne 'Current pool size is healthy.') {
                throw "Expected Info StatusSummary to use OkGuidance, got '$($measure.StatusSummary)'."
            }

            $findings = [System.Collections.Generic.List[psobject]]::new()
            Add-IISPerformanceFinding -Findings $findings -Measure $measure

            if ($findings.Count -ne 1) {
                throw "Expected one finding, got $($findings.Count)."
            }

            $detail = $findings[0].Detail
            if ($detail -notmatch 'Current pool size is healthy\.') {
                throw "Expected detail to include OkGuidance, got '$detail'."
            }
            if (($detail | Select-String -Pattern 'Pool size is informational\.' -AllMatches).Matches.Count -ne 1) {
                throw "Expected WhatToExpect text once in detail, got '$detail'."
            }
        }
    }
}
