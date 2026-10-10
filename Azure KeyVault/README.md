# KeyVaults Audit Lab 🔐

A deployable Azure Key Vault lab that generates realistic, high-volume `AuditEvent` activity so Key Vault logging, alerting and hunting queries can be built and validated against real data instead of guesswork.

The lab provisions Key Vaults, Entra app identities and an Automation Account that continuously simulates the behavior of applications, certificate operators and admins against those vaults.

## What does it do?

* 🗝️ **Key Vaults** — a mix of RBAC and access-policy vaults, soft delete enabled, one vault dedicated to delete/recover churn
* 👤 **App identities** — Entra app registrations/service principals for three roles (`App`, `CertOps`, `Reader`), each with least-privilege permissions
* 🤖 **Automation runbook** — a system-assigned managed identity runbook that authenticates as every identity and issues weighted, randomized Key Vault and ARM requests (reads, crypto operations, writes, admin changes)
* 💥 **Scenario coverage** — soft delete/recover, purge/restore, externally-signed certificate CSR + merge, cancelled certificate requests, vault delete/recover, and near-expiry/expiring objects
* 🏷️ **Request correlation** — every call is tagged with a distinct `User-Agent` per caller and an `x-ms-client-request-id`, so activity can be attributed back to a specific identity in the logs

## Prerequisites

```powershell
Install-Module Az.Accounts, Az.Resources, Az.Automation, Az.KeyVault, Microsoft.Graph.Authentication
```

* PowerShell 7.2+
* An Azure subscription with rights to create resource groups, Key Vaults, role assignments and an Automation Account
* An Entra ID account with `Application.ReadWrite.All` to create the app registrations

## Usage

### Deploy the lab

```powershell
./Deploy-KeyVaultAuditLab.ps1 -SubscriptionId <SubscriptionID> -ResourceGroupName <RG Name> -Location westeurope -VaultCount 3
```

The script is idempotent and re-running it will only fix drift (missing vaults, role assignments, expired app secrets, etc.). Key parameters:

* `-VaultCount` — number of Key Vaults to create (default `3`)
* `-AppIdentityCount` — number of app identities spread across the `App`, `CertOps` and `Reader` profiles (default `3`)
* `-RbacVaultRatio` — fraction of vaults using the RBAC permission model vs. access policies (default `0.5`)
* `-ScheduleIntervalHours` — how often the simulation runbook runs on its recurring schedule (default `1`)
* `-RotateAppSecrets` — force rotation of the app identity secrets on this run

Diagnostic settings are **not** created by this script; log collection is expected to be enforced separately, e.g. via Azure Policy.

### Run the simulation on demand

```powershell
Import-Module Az.Automation
Start-AzAutomationRunbook -ResourceGroupName rg-kv-auditlab -AutomationAccountName kvaudit-kvlab-aa -Name Invoke-KeyVaultActivitySimulation -Parameters @{ DurationMinutes = 10 }
```

The runbook also runs automatically on the recurring schedule created by the deploy script.

### Remove the lab

```powershell
./Remove-KeyVaultAuditLab.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -ResourceGroupName rg-kv-auditlab -WhatIf
```

Removes the resource group, purges the soft-deleted lab vaults and deletes the lab app registrations. Use `-KeepAppRegistrations` to leave the Entra app registrations in place, and drop `-WhatIf` to actually apply the changes.

## Repository Structure

```
Deploy-KeyVaultAuditLab.ps1              # Provisions the lab
Remove-KeyVaultAuditLab.ps1              # Tears the lab down
Runbooks/
  Invoke-KeyVaultActivitySimulation.ps1  # Automation runbook simulating vault activity
```
