using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

/// <summary>
/// A utility class to determine a process parent.
/// <remarks>
/// Adapted from <seealso href="https://stackoverflow.com/a/3346055/5069211">c# - How to get parent process in .NET in managed way - Stack Overflow</seealso>
/// </remarks>
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtils
{
	internal IntPtr Reserved1;
	internal IntPtr PebBaseAddress;
	internal IntPtr Reserved2_0;
	internal IntPtr Reserved2_1;
	internal IntPtr UniqueProcessId;
	internal IntPtr InheritedFromUniqueProcessId;

	[DllImport("ntdll.dll")]
	private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtils processInformation, int processInformationLength, out int returnLength);

	public static Process? GetParentWithWindow()
	{
		for (var parent = GetParentProcess(); parent is not null; parent = GetParentProcess(parent))
		{
			if (parent.MainWindowHandle > 0)
			{
				return parent;
			}
		}
		return null;
	}

	/// <summary>
	/// Gets the parent process of the current process.
	/// </summary>
	/// <returns>An instance of the Process class.</returns>
	public static Process? GetParentProcess()
	{
		return GetParentProcess(Process.GetCurrentProcess());
	}

	/// <summary>
	/// Gets the parent process of a specified process.
	/// </summary>
	/// <param name="handle">The process handle.</param>
	/// <returns>An instance of the Process class.</returns>
	public static Process? GetParentProcess(Process process)
	{
		nint handle;
		try
		{
			handle = process.Handle;
		}
		catch (Win32Exception)
		{
			return null;
		}

		ParentProcessUtils pbi = new ParentProcessUtils();
		int returnLength;
		int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
		if (status != 0)
			return null;

		try
		{
			return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
		}
		catch (ArgumentException)
		{
			return null;
		}
	}
}