using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Drawing2D;

[assembly: AssemblyTitle("Microchip faf-re builder")]
[assembly: AssemblyDescription("Build and install faf-re, Lag Test and configurable simulation threading")]
[assembly: AssemblyCompany("Microchip")]
[assembly: AssemblyProduct("Microchip faf-re builder")]
[assembly: AssemblyCopyright("Author: Microchip")]
[assembly: AssemblyVersion("2.0.0.0")]

internal sealed class VersionChoice
{
    public string Label, Revision;
    public override string ToString() { return Label; }
}

internal static class Setup
{
    internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16777216 };
    internal static string Prefs { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Forged Alliance Forever", "client.prefs"); } }
    internal static string Work { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microchip", "faf-re-builder"); } }
    internal static readonly string[] Hooks = { "lobby.lua", "connectiontest.lua", "connectionscore.lua" };
    internal static byte[] Resource(string name)
    {
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
        {
            if (stream == null) throw new InvalidDataException("Missing installer resource: " + name);
            using (var buffer = new MemoryStream()) { stream.CopyTo(buffer); return buffer.ToArray(); }
        }
    }
    internal static void CheckPath(string path)
    {
        for (var dir = new DirectoryInfo(Path.GetFullPath(path)); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Choose a folder without links or junctions.");
    }
    internal static Dictionary<string, object> ReadSettings(string prefs)
    {
        if (!File.Exists(prefs)) throw new IOException("FAF client settings were not found. Open and close the FAF client first.");
        return Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(prefs));
    }
    internal static Dictionary<string, object> GameSettings(Dictionary<string, object> settings)
    {
        object game;
        if (!settings.TryGetValue("forgedAlliance", out game) || !(game is Dictionary<string, object>)) throw new IOException("The FAF client settings format is unsupported.");
        return (Dictionary<string, object>)game;
    }
    internal static bool IsEngine(string path)
    {
        try
        {
            if (!Directory.Exists(Path.Combine(path, "fafengine"))) return false;
            using (var reader = new BinaryReader(File.OpenRead(Path.Combine(path, "main_x64.exe"))))
            {
                if (reader.ReadUInt16() != 0x5a4d) return false;
                reader.BaseStream.Position = 0x3c;
                int offset = reader.ReadInt32();
                if (offset < 64 || offset > reader.BaseStream.Length - 6) return false;
                reader.BaseStream.Position = offset;
                return reader.ReadUInt32() == 0x4550 && reader.ReadUInt16() == 0x8664;
            }
        }
        catch { return false; }
    }
    internal static List<string> Detect(string prefs, IEnumerable<string> candidates)
    {
        var paths = new List<string>();
        try
        {
            var game = GameSettings(ReadSettings(prefs)); object value;
            if (game.TryGetValue("executionDirectory", out value) && value is string) paths.Add((string)value);
            if (game.TryGetValue("executableDecorator", out value) && value is string)
            {
                string command = ((string)value).Trim();
                if (command.StartsWith("\""))
                {
                    int end = command.IndexOf('"', 1);
                    if (end > 1) paths.Add(Path.GetDirectoryName(command.Substring(1, end - 1)));
                }
            }
        }
        catch { /* A missing client preference file must not stop engine detection. */ }
        paths.AddRange(candidates);
        return paths.Where(p => !string.IsNullOrWhiteSpace(p) && IsEngine(p)).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
    internal static string WriteFiles(string backupRoot, Dictionary<string, byte[]> files)
    {
        foreach (string path in files.Keys)
        {
            CheckPath(Path.GetDirectoryName(path));
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Cannot replace linked files.");
        }
        string backup = Path.Combine(backupRoot, "lag-test-backups", Guid.NewGuid().ToString("N"));
        CheckPath(backup);
        // Client preferences can contain private account settings; do not inherit
        // the shared FAF data folder's read permissions for these backups.
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(backup, security);
        var originals = new Dictionary<string, string>(); int index = 0;
        foreach (string path in files.Keys)
        {
            string saved = null;
            if (File.Exists(path)) { saved = Path.Combine(backup, (++index) + "-" + Path.GetFileName(path)); File.Copy(path, saved); }
            originals.Add(path, saved);
        }
        File.WriteAllText(Path.Combine(backup, "restore-map.json"), Json.Serialize(originals));
        var changed = new List<string>();
        try
        {
            foreach (var file in files)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file.Key));
                changed.Add(file.Key); File.WriteAllBytes(file.Key, file.Value);
            }
        }
        catch (Exception original)
        {
            var errors = new List<string>();
            foreach (string path in changed)
                try
                {
                    if (originals[path] == null) File.Delete(path);
                    else if (!File.ReadAllBytes(path).SequenceEqual(File.ReadAllBytes(originals[path]))) File.Copy(originals[path], path, true);
                }
                catch { errors.Add(path); }
            if (errors.Count > 0) throw new IOException(original.Message + "\r\nSome files need restoring from: " + backup, original);
            throw;
        }
        return backup;
    }
    internal static int MaximumWorkers { get { return Math.Max(1, Math.Min(64, Environment.ProcessorCount)); } }
    internal static int[] Threading(string target)
    {
        string path = Path.Combine(target, "microchip-threading.json");
        if (!File.Exists(path)) return new[] { 0, MaximumWorkers, 0 };
        var value = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path));
        return new[] { Convert.ToBoolean(value["enabled"]) ? 1 : 0, Math.Max(1, Math.Min(MaximumWorkers, Convert.ToInt32(value["workers"]))), value.ContainsKey("allCores") && Convert.ToBoolean(value["allCores"]) ? 1 : 0 };
    }
    internal static string SetThreading(string target, bool enabled, int workers, bool allCores = false)
    {
        if (!IsEngine(target)) throw new IOException("Install faf-re first.");
        if (workers < 1 || workers > MaximumWorkers) throw new ArgumentOutOfRangeException("workers");
        var files = new Dictionary<string, byte[]>(); AddHooks(files, target);
        string lobby = Path.Combine(target, "fafengine", "lua", "ui", "lobby", "lobby.lua");
        files[lobby] = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Resource("lobby.lua")).Replace("local microchipSimWorkers = nil", "local microchipSimWorkers = " + (enabled ? workers : 0)));
        files[Path.Combine(target, "microchip-threading.json")] = Encoding.UTF8.GetBytes(Json.Serialize(new { enabled = enabled, workers = workers, allCores = allCores }));
        AddAffinity(files, target, allCores);
        return WriteFiles(target, files);
    }
    internal static void AddAffinity(Dictionary<string, byte[]> files, string target, bool allCores)
    {
        string path = Path.Combine(target, "init_faf.lua");
        string original = files.ContainsKey(path) ? Encoding.UTF8.GetString(files[path]) : File.ReadAllText(path);
        // Restore our own marked guards before applying the selected state.
        string restored = Regex.Replace(original, @"(?m)^(\s*)(if|elseif) false then -- Microchip all cores: (.+?)\r?$", "$1$3");
        string adjusted = restored;
        if (allCores)
        {
            int matches = 0;
            adjusted = Regex.Replace(restored, @"(?m)^(\s*)((if|elseif) (\(?systemAffinityMask >= (16777215|63)\)?) then)\r?$", match => {
                matches++; return match.Groups[1].Value + match.Groups[3].Value + " false then -- Microchip all cores: " + match.Groups[2].Value;
            });
            if (matches != 2) throw new IOException("This init_faf.lua has an unfamiliar CPU-affinity layout. No files were changed; leave Use all CPU cores off for this version.");
        }
        if (adjusted != original) files[path] = Encoding.UTF8.GetBytes(adjusted);
    }
    internal static void AddHooks(Dictionary<string, byte[]> files, string target)
    {
        foreach (string name in Hooks) files[Path.Combine(target, "fafengine", "lua", "ui", "lobby", name)] = Resource(name);
        if (File.Exists(Path.Combine(target, "microchip-threading.json")))
        {
            int[] saved = Threading(target);
            string lobby = Path.Combine(target, "fafengine", "lua", "ui", "lobby", "lobby.lua");
            files[lobby] = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Resource("lobby.lua")).Replace("local microchipSimWorkers = nil", "local microchipSimWorkers = " + (saved[0] != 0 ? saved[1] : 0)));
        }
    }
    internal static bool LagTestInstalled(string target)
    {
        return target != null && Hooks.All(name => File.Exists(Path.Combine(target, "fafengine", "lua", "ui", "lobby", name)));
    }
    internal static bool LagTestCurrent(string target)
    {
        if (!LagTestInstalled(target)) return false;
        var files = new Dictionary<string, byte[]>(); AddHooks(files, target);
        return files.All(file => File.ReadAllBytes(file.Key).SequenceEqual(file.Value));
    }
    internal static string InstallHooks(string target)
    {
        if (!IsEngine(target)) throw new IOException("Choose the folder containing the existing faf-re main_x64.exe and fafengine directory.");
        var files = new Dictionary<string, byte[]>(); AddHooks(files, target);
        if (File.Exists(Path.Combine(target, "microchip-threading.json"))) AddAffinity(files, target, Threading(target)[2] != 0);
        return WriteFiles(target, files);
    }
    internal static string InstallBuild(string root, string output, string revision, bool shortcut, string existingTarget = null)
    {
        root = Path.GetFullPath(root);
        string target = existingTarget ?? Path.Combine(root, "bin_x64"), original = Path.Combine(root, "bin");
        if (!File.Exists(Path.Combine(root, "fa_path.lua")) || !File.Exists(Path.Combine(original, "init_faf.lua"))) throw new IOException("Choose the FAF data folder containing fa_path.lua and bin. Launch a normal FAF game once first.");
        if (!IsEngine(output)) throw new IOException("The build did not produce a valid x64 engine and its fafengine folder.");
        var files = new Dictionary<string, byte[]>();
        foreach (string name in new[] { "main_x64.exe", "dxcompiler.dll", "dxil.dll" }) files.Add(Path.Combine(target, name), File.ReadAllBytes(Path.Combine(output, name)));
        string engineHooks = Path.Combine(output, "fafengine");
        if (Directory.Exists(engineHooks))
            foreach (string source in Directory.GetFiles(engineHooks, "*", SearchOption.AllDirectories))
                files.Add(Path.Combine(target, "fafengine", source.Substring(engineHooks.Length + 1)), File.ReadAllBytes(source));
        files[Path.Combine(target, "fafengine", "lua", "options", "options.lua")] = Resource("options.lua");
        AddHooks(files, target);
        foreach (string source in Directory.GetFiles(original, "*.lua")) files[Path.Combine(target, Path.GetFileName(source))] = File.ReadAllBytes(source);
        if (File.Exists(Path.Combine(target, "microchip-threading.json"))) AddAffinity(files, target, Threading(target)[2] != 0);
        files[Path.Combine(target, "microchip-install.json")] = Encoding.UTF8.GetBytes(Json.Serialize(new { revision = revision, source = "https://github.com/Draiget/faf-re", author = "Microchip", installedUtc = DateTime.UtcNow.ToString("o") }));
        if (shortcut)
        {
            string temporary = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".lnk");
            try
            {
                Type type = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(type);
                object link = type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { temporary });
                Type linkType = link.GetType();
                linkType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, link, new object[] { Path.Combine(target, "main_x64.exe") });
                linkType.InvokeMember("Arguments", BindingFlags.SetProperty, null, link, new object[] { "/init init_faf.lua /nobugreport /con lua_AllowPrecompiledChunks=1;ren_GpuSelectBrackets=0" });
                linkType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, link, new object[] { target });
                linkType.InvokeMember("Save", BindingFlags.InvokeMethod, null, link, null);
                files[Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "FAF Rebuilt x64.lnk")] = File.ReadAllBytes(temporary);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        return WriteFiles(root, files);
    }
    internal static string Connect(string target, string prefs)
    {
        if (!IsEngine(target) || !File.Exists(Path.Combine(target, "init_faf.lua"))) throw new IOException("Install a ready-to-run faf-re engine first.");
        var settings = ReadSettings(prefs); var game = GameSettings(settings);
        game["executionDirectory"] = target;
        game["executableDecorator"] = "\"" + Path.Combine(target, "main_x64.exe") + "\" /con lua_AllowPrecompiledChunks=1;ren_GpuSelectBrackets=0";
        return WriteFiles(target, new Dictionary<string, byte[]> { { Path.GetFullPath(prefs), Encoding.UTF8.GetBytes(Json.Serialize(settings)) } });
    }
    // True when the FAF client currently launches games with this faf-re engine.
    internal static bool UsesX64(string prefs, string target)
    {
        try
        {
            object directory; var game = GameSettings(ReadSettings(prefs));
            return target != null && game.TryGetValue("executionDirectory", out directory) && directory is string
                && string.Equals(Path.GetFullPath((string)directory).TrimEnd('\\'), Path.GetFullPath(target).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
    // Restores FAF's own launch defaults so the client runs the classic ForgedAlliance.exe again.
    internal static string UseClassic(string backupRoot, string prefs)
    {
        var settings = ReadSettings(prefs); var game = GameSettings(settings);
        game.Remove("executionDirectory");
        game["executableDecorator"] = "\"%s\"";
        return WriteFiles(backupRoot, new Dictionary<string, byte[]> { { Path.GetFullPath(prefs), Encoding.UTF8.GetBytes(Json.Serialize(settings)) } });
    }
    internal static string Quote(string value)
    {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\') { slashes++; continue; }
            result.Append('\\', character == '"' ? slashes * 2 + 1 : slashes);
            result.Append(character); slashes = 0;
        }
        result.Append('\\', slashes * 2); return result.Append('"').ToString();
    }
    internal static object Api(string endpoint)
    {
        using (var client = new WebClient())
        {
            client.Headers["User-Agent"] = "Microchip-faf-re-builder";
            return Json.DeserializeObject(client.DownloadString("https://api.github.com/repos/Draiget/faf-re/" + endpoint));
        }
    }
    internal static List<VersionChoice> Versions()
    {
        var latest = (Dictionary<string, object>)((object[])Api("commits?per_page=1"))[0];
        string sha = (string)latest["sha"];
        var choices = new List<VersionChoice> { new VersionChoice { Label = "Latest (" + sha.Substring(0, 8) + ")", Revision = sha } };
        object[] tags;
        try { tags = (object[])Api("tags?per_page=50"); } catch (WebException) { tags = new object[0]; }
        foreach (Dictionary<string, object> tag in tags)
        {
            var commit = (Dictionary<string, object>)tag["commit"];
            choices.Add(new VersionChoice { Label = (string)tag["name"] + " (" + ((string)commit["sha"]).Substring(0, 8) + ")", Revision = (string)commit["sha"] });
        }
        const string previous = "e4cc5d8b03cc29a9100fa29f08eea57f6aaa0a95";
        if (!choices.Any(choice => choice.Revision == previous))
            choices.Add(new VersionChoice { Label = "Previously working - 26 Oct 2026 (e4cc5d8b)", Revision = previous });
        return choices;
    }
    internal static string RunWorker(string mode, string revision, Action<string> progress)
    {
        string run = Path.Combine(Work, "runs", Guid.NewGuid().ToString("N")); CheckPath(run); Directory.CreateDirectory(run);
        string script = Path.Combine(run, "Build-FafRe.ps1"), result = Path.Combine(run, "result.json"), log = Path.Combine(run, "build.log");
        File.WriteAllBytes(script, Resource("worker.ps1"));
        progress("Log: " + log);
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"));
        start.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Quote(script) + " -Mode " + mode + " -Workspace " + Quote(Work) + " -ResultFile " + Quote(result) + (mode == "Build" ? " -Revision " + revision : "");
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using (var writer = new StreamWriter(log, false, Encoding.UTF8))
        using (var process = new Process { StartInfo = start })
        {
            Action<string> line = text => { if (text == null) return; lock (writer) { writer.WriteLine(text); writer.Flush(); } progress(text); };
            process.OutputDataReceived += (s, e) => line(e.Data); process.ErrorDataReceived += (s, e) => line(e.Data);
            process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine(); process.WaitForExit();
            if (!File.Exists(result)) throw new IOException("The operation failed before it could report a result. Log: " + log);
            if (process.ExitCode != 0)
            {
                var failure = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(result));
                object reason;
                throw new IOException((failure.TryGetValue("error", out reason) ? Convert.ToString(reason) : "The operation failed.") + "\r\n\r\nLog: " + log);
            }
        }
        var data = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(result));
        if (!(bool)data["success"]) throw new IOException((string)data["error"]);
        return mode == "Build" ? (string)data["output"] : null;
    }
}

internal sealed class FafButton : Button
{
    bool hover, pressed;
    internal bool Primary;
    internal FafButton() { FlatStyle = FlatStyle.Flat; Cursor = Cursors.Hand; SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true); }
    protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hover = pressed = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnPaint(PaintEventArgs e)
    {
        var bounds = new Rectangle(0, 0, Width - 1, Height - 1);
        Color top = !Enabled ? Color.FromArgb(27, 36, 43) : pressed ? Color.FromArgb(20, 46, 58) : hover ? Color.FromArgb(51, 80, 94) : Color.FromArgb(39, 57, 69);
        using (var fill = new LinearGradientBrush(bounds, top, Color.FromArgb(15, 26, 34), 90f)) e.Graphics.FillRectangle(fill, bounds);
        using (var edge = new Pen(Enabled && (hover || Primary) ? Color.FromArgb(105, 211, 228) : Color.FromArgb(64, 85, 98))) e.Graphics.DrawRectangle(edge, bounds);
        using (var highlight = new Pen(Color.FromArgb(68, 93, 106))) e.Graphics.DrawLine(highlight, 5, 2, Width - 6, 2);
        TextRenderer.DrawText(e.Graphics, Text, Font, bounds, Enabled ? Color.FromArgb(220, 239, 244) : Color.FromArgb(103, 121, 133), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(e.Graphics, new Rectangle(4, 4, Width - 9, Height - 9), Color.LightCyan, Color.Transparent);
    }
}

internal sealed class BuilderForm : Form
{
    readonly ComboBox versions = new ComboBox { Left = 145, Top = 72, Width = 410, DropDownStyle = ComboBoxStyle.DropDownList };
    readonly ComboBox engines = new ComboBox { Left = 145, Top = 112, Width = 410, DropDownStyle = ComboBoxStyle.DropDownList };
    readonly TextBox data = new TextBox { Left = 145, Top = 152, Width = 410 };
    readonly TextBox log = new TextBox { Left = 20, Top = 302, Width = 650, Height = 210, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
    readonly CheckBox closed = new CheckBox { Left = 20, Top = 193, Width = 650, Text = "I have closed the FAF client and game." };
    readonly Label installedInfo = new Label { Left = 20, Top = 216, Width = 650, Height = 18 };
    readonly FafButton install = new FafButton { Left = 20, Top = 238, Width = 200, Height = 38, Text = "Install faf-re" };
    readonly FafButton lag = new FafButton { Left = 237, Top = 238, Width = 200, Height = 38, Text = "Install Lag Test" };
    readonly FafButton connect = new FafButton { Left = 454, Top = 238, Width = 216, Height = 38, Text = "Connect with FAF client" };
    readonly Label modeInfo = new Label();
    readonly FafButton refresh =new FafButton { Left = 565, Top = 69, Width = 105, Text = "Refresh" };
    readonly FafButton browseEngine = new FafButton { Left = 565, Top = 109, Width = 105, Text = "Browse..." };
    readonly FafButton browseData = new FafButton { Left = 565, Top = 149, Width = 105, Text = "Browse..." };
    readonly CheckBox parallel = new CheckBox { Text = "Enable parallel simulation", AutoSize = true };
    readonly CheckBox allCores = new CheckBox { Text = "Use all CPU cores (remove FAF exclusions)", AutoSize = true };
    readonly NumericUpDown workers = new NumericUpDown { Minimum = 1, Maximum = Setup.MaximumWorkers, Value = Setup.MaximumWorkers };
    readonly FafButton applyThreading = new FafButton { Text = "Apply threading" };
    bool busy;
    string Engine { get { return engines.SelectedItem as string; } }
    internal BuilderForm()
    {
        Text = "Microchip faf-re builder"; ClientSize = new Size(900, 870);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        AutoScaleMode = AutoScaleMode.Dpi; Font = new Font("Segoe UI", 10f);
        BackColor = Color.FromArgb(8, 14, 20); ForeColor = Color.FromArgb(218, 231, 238);
        DoubleBuffered = true;
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
        Controls.AddRange(new Control[] { versions, engines, data, closed, installedInfo, modeInfo, install, lag, connect, refresh, browseEngine, browseData, log, parallel, workers, applyThreading, allCores });
        ApplyTheme();
        data.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FAForever");
        Detect();
        engines.SelectedIndexChanged += delegate { LoadThreading(); UpdateButtons(); };
        parallel.CheckedChanged += delegate { UpdateButtons(); };
        applyThreading.Click += async delegate { await Act("Threading"); };
        data.TextChanged += delegate { if (!busy) Detect(); };
        refresh.Click += async delegate { await LoadVersions(); };
        browseEngine.Click += delegate { using (var picker = new FolderBrowserDialog()) { if (picker.ShowDialog(this) == DialogResult.OK) { if (!Setup.IsEngine(picker.SelectedPath)) { MessageBox.Show(this, "Choose the folder containing faf-re main_x64.exe and fafengine."); return; } Detect(picker.SelectedPath); } } };
        browseData.Click += delegate { using (var picker = new FolderBrowserDialog()) { if (picker.ShowDialog(this) == DialogResult.OK) data.Text = picker.SelectedPath; } };
        install.Click += async delegate { await Act("Build"); };
        lag.Click += async delegate { await Act("Lag"); };
        connect.Click += async delegate { await Act(Setup.UsesX64(Setup.Prefs, Engine) ? "Classic" : "Connect"); };
        Shown += async delegate { await LoadVersions(); };
        FormClosing += (s, e) => { if (busy) { e.Cancel = true; MessageBox.Show(this, "Please wait for the current operation to finish."); } };
    }
    void Caption(string text, int x, int y, int width, float size, Color color, FontStyle style = FontStyle.Regular)
    {
        Controls.Add(new Label { Text = text, Left = x, Top = y, Width = width, Height = size >= 20 ? 42 : 26, ForeColor = color, BackColor = Color.Transparent, Font = new Font("Segoe UI", size, style) });
    }
    void ApplyTheme()
    {
        Color cyan = Color.FromArgb(114, 215, 230), muted = Color.FromArgb(145, 169, 184);
        Caption("FORGED ALLIANCE FOREVER", 30, 15, 500, 9, cyan, FontStyle.Bold);
        Caption("Microchip faf-re builder", 28, 36, 690, 25, ForeColor, FontStyle.Bold);
        Caption("Engine installation   /   Lag Test   /   FAF connection", 31, 84, 650, 10, muted);
        Caption("01  /  INSTALLATION", 44, 139, 500, 11, cyan, FontStyle.Bold);
        Caption("Version", 44, 183, 150, 10, ForeColor);
        Caption("Installed faf-re", 44, 229, 150, 10, ForeColor);
        Caption("FAF data folder", 44, 275, 150, 10, ForeColor);
        versions.SetBounds(208, 177, 514, 30); refresh.SetBounds(738, 177, 116, 30);
        engines.SetBounds(208, 223, 514, 30); browseEngine.SetBounds(738, 223, 116, 30);
        data.SetBounds(208, 269, 514, 30); browseData.SetBounds(738, 269, 116, 30);
        installedInfo.SetBounds(208, 312, 646, 22); installedInfo.ForeColor = cyan;
        parallel.SetBounds(44, 345, 300, 26);
        parallel.ForeColor = ForeColor; parallel.BackColor = Color.FromArgb(17, 28, 38);
        Caption("Workers", 380, 347, 100, 10, ForeColor);
        workers.SetBounds(480, 343, 90, 30);
        workers.BackColor = Color.FromArgb(8, 18, 26); workers.ForeColor = ForeColor;
        applyThreading.SetBounds(680, 340, 174, 36);
        allCores.SetBounds(44, 378, 600, 26); allCores.ForeColor = ForeColor; allCores.BackColor = Color.FromArgb(17, 28, 38);
        Caption("Up to " + Setup.MaximumWorkers + " CPU threads detected. CPU access changes require a new game process.", 44, 411, 810, 9, muted);
        closed.SetBounds(44, 447, 810, 26); closed.ForeColor = muted; closed.BackColor = Color.FromArgb(17, 28, 38);
        Caption("02  /  BUILD ENGINE", 44, 519, 240, 10, cyan, FontStyle.Bold);
        Caption("03  /  PREPARE LOBBY", 334, 519, 240, 10, cyan, FontStyle.Bold);
        Caption("04  /  FAF MODE", 624, 519, 240, 10, cyan, FontStyle.Bold);
        install.SetBounds(44, 554, 232, 44); install.Primary = true;
        lag.SetBounds(334, 554, 232, 44); connect.SetBounds(624, 554, 232, 44);
        Caption("Download, build and install faf-re.", 44, 611, 236, 9, muted);
        Caption("Detect, install or update Lag Test.", 334, 611, 236, 9, muted);
        modeInfo.SetBounds(624, 611, 236, 26); modeInfo.ForeColor = cyan; modeInfo.BackColor = Color.Transparent; modeInfo.Font = new Font("Segoe UI", 9f);
        Caption("ACTIVITY LOG", 30, 674, 300, 10, cyan, FontStyle.Bold);
        log.SetBounds(30, 706, 840, 124); log.Font = new Font("Consolas", 9f);
        log.BackColor = Color.FromArgb(6, 12, 17); log.ForeColor = Color.FromArgb(169, 198, 212); log.BorderStyle = BorderStyle.FixedSingle;
        Caption("AUTHOR  /  Microchip", 30, 842, 350, 9, muted);
        Caption("WINDOWS  /  X64", 726, 842, 150, 9, cyan);
        foreach (var combo in new[] { versions, engines })
        {
            combo.FlatStyle = FlatStyle.Flat; combo.BackColor = Color.FromArgb(8, 18, 26); combo.ForeColor = ForeColor;
            combo.DrawMode = DrawMode.OwnerDrawFixed; combo.ItemHeight = 24; combo.DropDownWidth = 646;
            combo.DrawItem += (sender, e) => {
                if (e.Index < 0) return;
                var box = (ComboBox)sender;
                bool selected = (e.State & DrawItemState.Selected) != 0;
                using (var brush = new SolidBrush(selected ? Color.FromArgb(36, 68, 83) : Color.FromArgb(8, 18, 26))) e.Graphics.FillRectangle(brush, e.Bounds);
                var bounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, Convert.ToString(box.Items[e.Index]), box.Font, bounds, box.Enabled ? ForeColor : muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
                e.DrawFocusRectangle();
            };
        }
        data.BackColor = Color.FromArgb(8, 18, 26); data.ForeColor = ForeColor; data.BorderStyle = BorderStyle.FixedSingle;
        foreach (var button in new[] { install, lag, connect, refresh, browseEngine, browseData, applyThreading }) button.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using (var fill = new LinearGradientBrush(new Rectangle(0, 0, Width, 112), Color.FromArgb(30, 48, 61), Color.FromArgb(8, 14, 20), 0f)) e.Graphics.FillRectangle(fill, 0, 0, Width, 112);
        using (var accent = new Pen(Color.FromArgb(114, 215, 230), 2)) e.Graphics.DrawLine(accent, 30, 112, 155, 112);
        foreach (var rect in new[] { new Rectangle(24, 126, 852, 362), new Rectangle(24, 504, 272, 148), new Rectangle(314, 504, 272, 148), new Rectangle(604, 504, 272, 148) })
        {
            int cut = 9;
            var points = new[] { new Point(rect.Left + cut, rect.Top), new Point(rect.Right - cut, rect.Top), new Point(rect.Right, rect.Top + cut), new Point(rect.Right, rect.Bottom - cut), new Point(rect.Right - cut, rect.Bottom), new Point(rect.Left + cut, rect.Bottom), new Point(rect.Left, rect.Bottom - cut), new Point(rect.Left, rect.Top + cut) };
            using (var fill = new SolidBrush(Color.FromArgb(17, 28, 38))) e.Graphics.FillPolygon(fill, points);
            using (var border = new Pen(Color.FromArgb(52, 78, 94))) e.Graphics.DrawPolygon(border, points);
        }
        using (var border = new Pen(Color.FromArgb(52, 78, 94))) e.Graphics.DrawLine(border, 30, 835, 870, 835);
    }
    void Progress(string text)
    {
        if (IsDisposed) return;
        BeginInvoke((Action)(() => { if (log.TextLength > 120000) log.Text = log.Text.Substring(log.TextLength - 60000); log.AppendText(text + Environment.NewLine); }));
    }
    void Detect(string extra = null)
    {
        string selected = extra ?? Engine;
        var candidates = new List<string> { Path.Combine(data.Text, "bin_x64"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FAForever", "bin_x64") };
        if (selected != null) candidates.Insert(0, selected);
        var found = Setup.Detect(Setup.Prefs, candidates);
        engines.Items.Clear(); engines.Items.AddRange(found.Cast<object>().ToArray());
        if (found.Count > 0) engines.SelectedItem = selected != null && found.Contains(selected) ? selected : found[0];
        if (Engine != null)
        {
            string parent = Path.GetDirectoryName(Engine);
            if (File.Exists(Path.Combine(parent, "fa_path.lua")) && data.Text != parent) data.Text = parent;
        }
        installedInfo.Text = Engine == null ? "No existing faf-re found. Select a version and click Install faf-re." : "Existing faf-re found; installed version unknown.";
        if (Engine != null)
            try
            {
                var info = Setup.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(Engine, "microchip-install.json")));
                string revision = (string)info["revision"];
                if (revision.Length >= 8) installedInfo.Text = "Installed version: " + revision.Substring(0, 8);
            }
            catch { }
        LoadThreading(); UpdateButtons();
    }
    void LoadThreading()
    {
        try {
            int[] saved = Engine == null ? new[] { 0, Setup.MaximumWorkers, 0 } : Setup.Threading(Engine);
            parallel.Checked = saved[0] != 0; workers.Value = saved[1]; allCores.Checked = saved[2] != 0;
        } catch (Exception error) { Progress("Could not read threading settings: " + error.Message); }
    }
    void UpdateButtons()
    {
        install.Text = Engine == null ? "Install faf-re" : "Update / install version";
        install.Enabled = !busy && versions.SelectedItem != null;
        lag.Enabled = applyThreading.Enabled = !busy && Engine != null;
        bool x64 = Setup.UsesX64(Setup.Prefs, Engine);
        connect.Text = x64 ? "Switch to classic FAF" : "Switch to x64 faf-re";
        connect.Enabled = !busy && (Engine != null || x64);
        modeInfo.Text = x64 ? "FAF currently launches: x64 faf-re" : "FAF currently launches: classic";
        try { lag.Text = Setup.LagTestCurrent(Engine) ? "Already installed" : Setup.LagTestInstalled(Engine) ? "Update Lag Test" : "Install Lag Test"; }
        catch { lag.Text = "Update Lag Test"; }
        allCores.Enabled = parallel.Enabled = !busy; workers.Enabled = !busy && parallel.Checked;
        versions.Enabled = refresh.Enabled = engines.Enabled = browseEngine.Enabled = browseData.Enabled = data.Enabled = closed.Enabled = !busy;
    }
    async Task LoadVersions()
    {
        busy = true; UpdateButtons();
        try { var values = await Task.Run(() => Setup.Versions()); versions.Items.Clear(); versions.Items.AddRange(values.Cast<object>().ToArray()); versions.SelectedIndex = 0; Progress("Latest upstream revision selected. " + values.Count + " versions available."); }
        catch (Exception error) { Progress("Could not load versions: " + error.Message + " Click Refresh to retry. Existing Lag Test and FAF connection controls still work offline."); }
        finally { busy = false; UpdateButtons(); }
    }
    async Task Act(string action)
    {
        if (action == "Lag" && Setup.LagTestCurrent(Engine)) { MessageBox.Show(this, "Lag Test is already installed and up to date.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        if (!closed.Checked) { MessageBox.Show(this, "Close the FAF client and game, then tick the confirmation box."); return; }
        // The client keeps its settings in memory and saves them on exit, which would undo a mode change.
        if ((action == "Connect" || action == "Classic") && Process.GetProcessesByName("faf-client").Length > 0)
        { MessageBox.Show(this, "The FAF client is still running (check the system tray). Quit it fully, then try again.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        string target = Engine, root = data.Text;
        bool useAllCores = allCores.Checked; bool enableWorkers = parallel.Checked; int workerCount = (int)workers.Value;
        var version = versions.SelectedItem as VersionChoice;
        if (action == "Build" && version == null) return;
        if (action == "Build" && (!File.Exists(Path.Combine(root, "fa_path.lua")) || !File.Exists(Path.Combine(root, "bin", "init_faf.lua")))) { MessageBox.Show(this, "Select your FAF data folder. Launch a normal FAF game once before setup."); return; }
        busy = true; UpdateButtons();
        try
        {
            string backup = await Task.Run(() => {
                if (action == "Threading") return Setup.SetThreading(target, enableWorkers, workerCount, useAllCores);
                if (action == "Connect") return Setup.Connect(target, Setup.Prefs);
                if (action == "Classic") return Setup.UseClassic(target ?? root, Setup.Prefs);
                if (action == "Lag") { Setup.RunWorker("Runtime", null, Progress); return Setup.InstallHooks(target); }
                Progress("Downloading/building " + version.Label + ". FAF launch settings will remain unchanged.");
                string output = Setup.RunWorker("Build", version.Revision, Progress);
                return Setup.InstallBuild(root, output, version.Revision, true, target);
            });
            Progress("Completed. Backup: " + backup);
            Detect(action == "Build" ? (target ?? Path.Combine(root, "bin_x64")) : target);
            MessageBox.Show(this, action == "Threading" ? "CPU settings saved. Close and relaunch the game to apply all changes." : action == "Connect" ? "FAF now launches x64 faf-re. Open FAF to play." : action == "Classic" ? "FAF now launches classic Forged Alliance. Open FAF to play." : "All installed, ready to go.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception error) { Progress("ERROR: " + error.Message); MessageBox.Show(this, error.Message, "Operation failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { busy = false; UpdateButtons(); }
    }
}

internal static class Installer
{
    [STAThread]
    static int Main(string[] args)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        if (args.Length == 1 && args[0] == "--verify") { foreach (string name in Setup.Hooks.Concat(new[] { "options.lua", "worker.ps1" })) if (Setup.Resource(name).Length == 0) return 1; return 0; }
        if (args.Length == 1 && args[0] == "--selftest") return BuilderTests.Run();
        if (!Environment.Is64BitOperatingSystem) { MessageBox.Show("64-bit Windows is required."); return 1; }
        Application.EnableVisualStyles(); Application.Run(new BuilderForm()); return 0;
    }
}
