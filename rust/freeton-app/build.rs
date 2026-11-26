fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../freeton_icon.ico");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../freeton_icon.ico")
        .set("ProductName", "Freeton VPN")
        .set("FileDescription", "Freeton VPN Desktop Client")
        .set("CompanyName", "pishun")
        .set("InternalName", "FreetonVPN.exe")
        .set("OriginalFilename", "FreetonVPN.exe")
        .set("FileVersion", "3.0.1.0")
        .set("ProductVersion", "3.0.1.0")
        .set_version_info(winresource::VersionInfo::FILEVERSION, 0x0003_0000_0001_0000)
        .set_version_info(
            winresource::VersionInfo::PRODUCTVERSION,
            0x0003_0000_0001_0000,
        )
        .set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="3.0.1.0" processorArchitecture="*" name="pishun.FreetonVPN" type="win32"/>
  <description>Freeton VPN Desktop Client</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/PM</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>"#,
        );

    if let Err(err) = res.compile() {
        panic!("failed to compile Windows resources for FreetonVPN.exe: {err}");
    }
}
