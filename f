commit 4566c8fb1a127f21434777eae9e7fef25f4bafad
Author: Your Name <pramod.7456@gmail.com>
Date:   Thu Jul 23 19:53:33 2026 +0100

    RFC mask for WEI is handled

commit 171fb58878040ea91f658d32ed22a453421fe200
Merge: 935a94c da1e9c4
Author: pramod7456 <164239016+pramod7456@users.noreply.github.com>
Date:   Thu Jul 23 11:02:21 2026 -0700

    Merge branch 'rdkcentral:develop' into ravi_connected_pillar

commit da1e9c40cf3c21931de789a985cd70816e096c1c
Author: Durmuş Koyuncu <63795253+dkyncu@users.noreply.github.com>
Date:   Thu Jul 23 10:10:21 2026 +0300

    RDKBWIFI-518: Report real device country code in EasyMesh device translation (#1275)
    
    The EasyMesh device translator hardcoded the device country to "US", so the
    actual regulatory country never propagated to the controller and
    Device.WiFi.DataElements Network.Device.{i}.CountryCode could not be reported.
    
    Report the device's country from the radio config (via country_code_conversion)
    when building the device object, falling back to US only when it is unavailable.
    
    Signed-off-by: Durmus Koyuncu <durmus.kyncu.kd@gmail.com>
    Co-authored-by: Narendra Varma Dandu <narendandu@gmail.com>

commit cf53b7a5b94a546203a6cd9f20a4b2e3adbaa41f
Author: Petro Krynytskyi <petr0krynytskiy@gmail.com>
Date:   Wed Jul 22 17:14:54 2026 +0300

    XB10-2702: Update default wl_mlo_config nvram setting (#1206)
    
    Reason for change: [MLO] Set MLD_Link_ID by default to "2 1 0 -1"
    Test Procedure: On boot after upgrade "WL MLO AP IDS assignment 2 1 0 -1".
                    MLO can be configured without reboots.
    Risks: Low
    Priority: P1
    
    Signed-off-by: Petro Krynytskyi <Petr0krynytskiy@gmail.com>
    Co-authored-by: Narendra Varma Dandu <narendandu@gmail.com>

commit eb8d58345fdb9259c96cbcd916e3868af649159e
Author: Vysakh A V <vysakhav@protonmail.com>
Date:   Wed Jul 22 14:04:41 2026 +0100

    RDKB-65709: In coperate XER2 Platform support in OneWifi (#1282)
    
    RDKB-65709: In coperate XER2 Platform support in OneWifi
    
    Reason for change: Added XER2 platform scpecific changes
    in OneWifi components to get the required features
    to be enabled in platform.
    
    Test Procedure:
    This change is part of intial bringup.
    Able to build full stack image
    Board is booting up properly and OneWifi process and scripts are running
    
    Priority:P2
    Signed-off-by: Vysakh A V <vysakh.venugopal@sky.uk>
    
    * Fix up build issue with onewifi
    
    * Updated the map for ovsdb for XER2
    
    * Update the mesh_setip.sh script
    
    ---------
    
    Signed-off-by: Vysakh A V <vysakh.venugopal@sky.uk>
    Co-authored-by: Vysakh A V <vysakh.venugopal@sky.uk>
    Co-authored-by: Sathish Kumar Gnanasekaran <gsathish86@gmail.com>

commit 3b33b9492af7ef306878ae4686a91721c2acb4b4
Author: Petro Krynytskyi <petr0krynytskiy@gmail.com>
Date:   Wed Jul 22 02:21:56 2026 +0300

    XB10-2872: Allow MLO link ID to be set only for private VAPs (#1280)
    
    Reason for change: [MLO] MLD_Link_ID reconfiguration could break MLO
    Test Procedure: Configure MLO, check MLO and client connectivity
    Risks: Medium
    Priority: P1
    
    Signed-off-by: Petro Krynytskyi <petr0krynytskiy@gmail.com>
    Co-authored-by: Narendra Varma Dandu <narendandu@gmail.com>

commit b284d90288f73ef436a77d656a6b3bc53c6c7f7a
Author: Rakhil P E <117166043+rakhilpe@users.noreply.github.com>
Date:   Tue Jul 21 11:44:32 2026 +0530

    RDKBWIFI-520: EasyMesh - Fix OneWifi crash with AP Metrics reporting. (#1277)
    
    Reason for change: Added NULL guard to prevent crash if associated_devices_map is NULL. Also addressed a wrong code comparison for radio index.
    Test Procedure: Ensure no crash issues with onewifi with AP Metrics reporting.
    Risks: Medium
    Priority: P1
    
    Signed-off-by: Rakhil P E <rakhilpe001@gmail.com>
    Co-authored-by: Narendra Varma Dandu <narendandu@gmail.com>

commit 935a94c59463b557c9fb637293ba4821978c92d7
Author: Your Name <pramod.7456@gmail.com>
Date:   Tue Jul 21 00:04:40 2026 +0100

    Removed wc and gc rfc kept only WEI RFC

commit e4f40289e9899b2d724169cd481fb815f4cbeec6
Author: Your Name <pramod.7456@gmail.com>
Date:   Wed Jul 15 19:38:57 2026 +0100

    Removed unwanted code

commit 0bf15eb414254bcd7960dd17e9e155bf19dda093
Author: Your Name <pramod.7456@gmail.com>
Date:   Tue Jul 14 18:24:25 2026 +0100

    added operating standards related
