. "AD-Functions.ps1"

$Tasks = Read-Host -Prompt "Seleccione una opción: 
1. Verificar credenciales AD.
2. Obtener integrantes de un grupo. 
3. Verificar si la cuenta está bloqueada.
4. Obtener el nombre de dominio de un puesto de trabajo.
"

switch ($task)
{
    1 {Test-ADCredential}
    2 {Get-NestedMember}
    3 {Get-AccountLockedOut}
    4 {Get-DomainComputer}
}
