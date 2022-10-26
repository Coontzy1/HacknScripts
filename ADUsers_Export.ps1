Write-Output test
# Path: testing.ps1
# Gathering all propeties of all users in Active Directory
# Exporting to .CSV file
Get-ADUser -Filter * -Properties * | Export-Csv -PATH C:\Temp\ADUsers.csv -NoTypeInformation