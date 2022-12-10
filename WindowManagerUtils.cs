using System.Runtime.InteropServices;

public static class WindowManagerUtils
{
	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool SetForegroundWindow(nint hWnd);
}
