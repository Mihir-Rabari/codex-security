import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, win32 } from "node:path";
import type { WindowsBinding } from "./windows-binding.mjs";

// Ask Windows to evaluate the actual descriptor, without creating another user.
const inspectAccess = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class DirectoryAccessProof {
    [StructLayout(LayoutKind.Sequential)]
    struct Request {
        public uint DesiredAccess;
        public IntPtr PrincipalSelfSid, ObjectTypeList;
        public uint ObjectTypeListLength;
        public IntPtr OptionalArguments;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Reply {
        public uint ResultListLength;
        public IntPtr GrantedAccessMask, SaclEvaluationResults, Error;
    }
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzInitializeResourceManager(uint flags, IntPtr access, IntPtr groups, IntPtr freeGroups, IntPtr name, out IntPtr manager);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzInitializeContextFromSid(uint flags, IntPtr sid, IntPtr manager, IntPtr expiration, long identifier, IntPtr arguments, out IntPtr context);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzAccessCheck(uint flags, IntPtr context, ref Request request, IntPtr audit, byte[] descriptor, IntPtr optionalDescriptors, uint count, ref Reply reply, IntPtr results);
    [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
    [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr manager);
    static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static bool CanRead(byte[] descriptor, string identity) {
        IntPtr manager = IntPtr.Zero, context = IntPtr.Zero;
        IntPtr sid = IntPtr.Zero, granted = IntPtr.Zero, error = IntPtr.Zero;
        try {
            Check(AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out manager));
            var principal = new SecurityIdentifier(identity);
            var bytes = new byte[principal.BinaryLength];
            principal.GetBinaryForm(bytes, 0);
            sid = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, sid, bytes.Length);
            Check(AuthzInitializeContextFromSid(2, sid, manager, IntPtr.Zero, 0, IntPtr.Zero, out context));
            granted = Marshal.AllocHGlobal(4);
            error = Marshal.AllocHGlobal(4);
            var request = new Request { DesiredAccess = 1 };
            var reply = new Reply { ResultListLength = 1, GrantedAccessMask = granted, Error = error };
            Check(AuthzAccessCheck(0, context, ref request, IntPtr.Zero, descriptor, IntPtr.Zero, 0, ref reply, IntPtr.Zero));
            return Marshal.ReadInt32(error) == 0 && (Marshal.ReadInt32(granted) & 1) != 0;
        } finally {
            if (context != IntPtr.Zero) AuthzFreeContext(context);
            if (manager != IntPtr.Zero) AuthzFreeResourceManager(manager);
            if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
            if (granted != IntPtr.Zero) Marshal.FreeHGlobal(granted);
            if (error != IntPtr.Zero) Marshal.FreeHGlobal(error);
        }
    }
}
'@
$acl = Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH
$descriptor = $acl.GetSecurityDescriptorBinaryForm()
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
$rules = @($acl.Access)
$principals = @($rules | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Select-Object -Unique)
$privateRules = @($rules | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -in @('S-1-3-4', 'S-1-5-18', 'S-1-5-32-544') -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
    $_.InheritanceFlags -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
})
$hash = [System.Security.Cryptography.SHA256]::Create()
try { $digest = [Convert]::ToBase64String($hash.ComputeHash($descriptor)) } finally { $hash.Dispose() }
[pscustomobject]@{
    digest = $digest
    protected = $acl.AreAccessRulesProtected
    privateRules = ($rules.Count -eq 3 -and $privateRules.Count -eq 3 -and $principals.Count -eq 3)
    owner = [DirectoryAccessProof]::CanRead($descriptor, $owner)
    system = [DirectoryAccessProof]::CanRead($descriptor, 'S-1-5-18')
    administrators = [DirectoryAccessProof]::CanRead($descriptor, 'S-1-5-32-544')
    everyone = [DirectoryAccessProof]::CanRead($descriptor, 'S-1-1-0')
} | ConvertTo-Json -Compress
`;

export function privateDirectoryProof(root: string, native: WindowsBinding) {
  const system = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
  function access(path: string) {
    return JSON.parse(
      execFileSync(
        join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(inspectAccess, "utf16le").toString("base64"),
        ],
        {
          encoding: "utf8",
          windowsHide: true,
          env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: path },
        },
      ),
    ) as {
      digest: string;
      protected: boolean;
      privateRules: boolean;
      owner: boolean;
      system: boolean;
      administrators: boolean;
      everyone: boolean;
    };
  }
  const bytes = (path: string) =>
    Buffer.from(win32.toNamespacedPath(path), "utf16le");
  const parent = join(root, "broad-parent");
  assert.equal(native.createWindowsDirectories(bytes(parent)), 0);
  execFileSync(
    join(system, "icacls.exe"),
    [parent, "/grant", "*S-1-1-0:(OI)(CI)F"],
    { windowsHide: true },
  );
  const before = access(parent);
  assert(before.everyone, "Permissive parent must grant outsider read access");

  const inherited = join(parent, "default-directory");
  assert.equal(native.createWindowsDirectories(bytes(inherited)), 0);
  assert(
    access(inherited).everyone,
    "Default directory creation must still inherit permissions",
  );

  const first = join(parent, "private-parent");
  const state = join(first, "private-state");
  assert.equal(native.createWindowsDirectories(bytes(state), true), 0);
  for (const path of [first, state]) {
    const permissions = access(path);
    assert(
      permissions.protected && permissions.privateRules,
      "Every new directory must have only protected inheritable private grants",
    );
    assert(
      permissions.owner && permissions.system && permissions.administrators,
      "Owner, SYSTEM and administrators must retain access",
    );
    assert(
      !permissions.everyone,
      "An unrelated principal must not read the private directory",
    );
  }
  const file = join(state, "synthetic-state");
  writeFileSync(file, "synthetic private state\n");
  assert(
    !access(file).everyone,
    "Files must inherit the private directory permissions",
  );
  assert.equal(native.createWindowsDirectories(bytes(parent), true), 0);
  assert(
    access(parent).digest === before.digest,
    "Existing directory permissions must remain unchanged",
  );
  return true;
}
