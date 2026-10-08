# Targets for maintenance\Remove-OldFiles.ps1. Copy, adjust and pass with -ConfigPath.
@{
    # Every target must be inside this folder.
    AllowedRoot  = 'D:\Exchange'

    # Refuse paths with fewer segments than this (D:\Exchange\Erp = 3).
    MinPathDepth = 4

    LogPath      = 'D:\Scripts\Logs'

    Targets      = @(
        @{ Path = 'D:\Exchange\Erp\Out\Orders\Archive';   Days = 30; Filter = '*';     Recurse = $true;  RemoveEmptyDirs = $true }
        @{ Path = 'D:\Exchange\Erp\Out\Materials\Archive'; Days = 30; Filter = '*';     Recurse = $true;  RemoveEmptyDirs = $true }
        @{ Path = 'D:\Exchange\Edi\In\Processed';          Days = 14; Filter = '*.xml'; Recurse = $false }
        @{ Path = 'D:\Exchange\Labels\Printed';            Days = 7;  Filter = '*.pdf'; Recurse = $true;  RemoveEmptyDirs = $false }
    )
}
