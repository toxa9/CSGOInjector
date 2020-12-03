using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.IO;

namespace CSGOInjector
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_HIDE = 0x0;
        private const int SW_SHOW = 0x5;


        [STAThread]
        static void Main(string[] args)
        {
            IntPtr handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            try
            {
                if (VACBypass.Run(GetPathDLL()))
                {
                    MessageBox.Show("DLL injected!", "Success!", MessageBoxButtons.OK, MessageBoxIcon.Information, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                }
                else
                {
                    MessageBox.Show("Failed!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static string GetPathDLL()
        {
            string dllPath = string.Empty;

            using (OpenFileDialog fileDialog = new OpenFileDialog())
            {
                fileDialog.InitialDirectory = Directory.GetCurrentDirectory();
                fileDialog.Filter = "DLL files (*.dll)|*.dll";
                fileDialog.FilterIndex = 2;
                fileDialog.RestoreDirectory = true;

                if (fileDialog.ShowDialog() == DialogResult.OK)
                {
                    dllPath = fileDialog.FileName;
                }
                else
                {
                    throw new ApplicationException("Dll opening error");
                }
            }

            return dllPath;
        }
    }
}