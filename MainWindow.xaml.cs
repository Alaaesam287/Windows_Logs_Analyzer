using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;


namespace Log_Analyzer
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }



        // Event handler for Analyze button click
        private void AnalyzeButton_Click(object sender, RoutedEventArgs e)
        {
            string logType = ((ComboBoxItem)LogTypeComboBox.SelectedItem)?.Content.ToString();
            DateTime? startDate = StartDatePicker.SelectedDate;
            DateTime? endDate = EndDatePicker.SelectedDate;

            if (logType != null && startDate.HasValue && endDate.HasValue)
            {
                DisplayLogs(logType, startDate.Value, endDate.Value);
            }
            else
            {
                MessageBox.Show("Please select a log type and a valid date range.");
            }
        }

        private void DisplayLogs(string logType, DateTime startDate, DateTime endDate)
        {
            try
            {
                EventLog eventLog = logType switch
                {
                    "Application" => new EventLog("Application"),
                    "System" => new EventLog("System"),
                    "Security" => new EventLog("Security"),
                    _ => null
                };

                if (eventLog != null)
                {
                    var logEntries = eventLog.Entries.Cast<EventLogEntry>()
                        .Where(entry => entry.TimeGenerated >= startDate && entry.TimeGenerated <= endDate)
                        .ToList();

                    var suspiciousLogs = logEntries
                        .Where(entry => IsSuspiciousLog(entry))
                        .ToList();

                    MessageBox.Show($"Total logs: {logEntries.Count}\nSuspicious logs: {suspiciousLogs.Count}");

                    CustomizeAndExportLogs(logEntries, suspiciousLogs, startDate, endDate);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred while fetching logs: " + ex.Message);
            }
        }

        private bool IsSuspiciousLog(EventLogEntry entry)
        {
            string[] suspiciousKeywords = { "error", "failed", "unauthorized", "critical", "malware", "attack", "denied", "virus", "trojan", "ransomware", "file tampering", "unauthorized file modification",
                "login failure", "invalid login", "access denied", "security breach", "data breach", "intrusion detected", "unauthorized entry", "zero-day", "advanced persistent threat",
                "rootkit", "phishing", "spear phishing", "fraudulent email", "data leakage","data exfiltration", "information leak", "brute force", "password attempt",
                "credential stuffing", "network intrusion", "spoofing", "ddos", "denial of service","backdoor", "exploit", "root privilege", "unauthorized access attempt",
                "account compromise", "escalated privileges", "insider threat", "malicious insider","compromised account"};

            EventLogEntryType[] suspiciousTypes = { EventLogEntryType.Error, EventLogEntryType.FailureAudit };

            return suspiciousKeywords.Any(keyword => entry.Message.Contains(keyword, StringComparison.OrdinalIgnoreCase)) ||
                   suspiciousTypes.Contains(entry.EntryType);
        }

        private void CustomizeAndExportLogs(
            List<EventLogEntry> allLogs,
            List<EventLogEntry> suspiciousLogs,
            DateTime startDate,
            DateTime endDate)
        {
            // SaveFileDialog for logs
            SaveFileDialog logSaveDialog = new SaveFileDialog
            {
                Title = "Save Exported Logs",
                Filter = "Text Files (*.txt)|*.txt",
                DefaultExt = "txt",
                FileName = $"LogAnalysis_{startDate:yyyyMMdd}_{endDate:yyyyMMdd}.txt"
            };

            if (logSaveDialog.ShowDialog() == true)
            {
                string logFilePath = logSaveDialog.FileName;

                try
                {
                    // Export logs to text file
                    ExportLogsToTxt(logFilePath, allLogs, suspiciousLogs, startDate, endDate);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error during export: " + ex.Message);
                }
            }
        }

        private void ExportLogsToTxt(string filePath, List<EventLogEntry> allLogs, List<EventLogEntry> suspiciousLogs, DateTime startDate, DateTime endDate)
        {
            using var writer = new StreamWriter(filePath);
            writer.WriteLine("Log Analysis Report");
            writer.WriteLine($"Date Range: {startDate.ToShortDateString()} - {endDate.ToShortDateString()}");
            writer.WriteLine(new string('-', 80));
            writer.WriteLine($"Total logs: {allLogs.Count}");
            writer.WriteLine($"Suspicious logs: {suspiciousLogs.Count}");
            writer.WriteLine(new string('-', 80));

            writer.WriteLine("Suspicious Logs Summary:");
            foreach (var entry in suspiciousLogs)
            {
                writer.WriteLine($"Event Source: {entry.Source}");
                writer.WriteLine($"Time Generated: {entry.TimeGenerated}");
                writer.WriteLine($"Message: {entry.Message}");
                writer.WriteLine($"Event Type: {entry.EntryType}");
                writer.WriteLine(new string('-', 80));
            }
        }


        private async Task<List<(DateTime timestamp, double cpuUsage, double memoryUsage)>> GetCpuMemoryUsageAsync(DateTime startDate, DateTime endDate)
        {
            var data = new List<(DateTime timestamp, double cpuUsage, double memoryUsage)>();

            PerformanceCounter cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            PerformanceCounter memoryCounter = new PerformanceCounter("Memory", "Available MBytes");

            // Stabilize CPU counter
            for (int i = 0; i < 3; i++)
            {
                _ = cpuCounter.NextValue();
                await Task.Delay(500); // Asynchronous delay
            }

            DateTime currentTime = startDate;

            while (currentTime <= endDate)
            {
                try
                {
                    float cpuUsage = cpuCounter.NextValue();
                    float availableMemory = memoryCounter.NextValue();

                    // Retrieve total memory dynamically to account for changes
                    float totalMemory = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory / (1024 * 1024); // Convert bytes to MB

                    // Calculate memory usage as a percentage
                    float memoryUsage = 100 - ((availableMemory / totalMemory) * 100);

                    // Clamp memory usage to 0-100 in case of anomalies
                    memoryUsage = Math.Max(0, Math.Min(100, memoryUsage));

                    data.Add((currentTime, cpuUsage, memoryUsage));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error collecting data: {ex.Message}");
                }

                await Task.Delay(1000); // Asynchronous 1-second interval
                currentTime = currentTime.AddMinutes(5); // Update timestamp for each interval
            }

            return data;
        }

        private async void VisualizeButton_Click(object sender, RoutedEventArgs e)
        {
            // Disable the button to prevent multiple clicks
            VisualizeButton.IsEnabled = false;

            // Collect data asynchronously for the last 1 hour
            var cpuMemoryData = await GetCpuMemoryUsageAsync(DateTime.Now.AddHours(-1), DateTime.Now);

            // Aggregate data into 1-minute intervals for visualization
            var aggregatedData = cpuMemoryData
                .GroupBy(d => new DateTime(d.timestamp.Year, d.timestamp.Month, d.timestamp.Day, d.timestamp.Hour, d.timestamp.Minute, 0)) // Round to the nearest minute
                .Select(g => (
                    timestamp: g.Key,
                    cpuUsage: g.Average(x => x.cpuUsage),
                    memoryUsage: g.Average(x => x.memoryUsage)
                )).ToList();

            // Open a visualization window
            Window1 window1 = new Window1(aggregatedData);
            window1.Show();

            // Re-enable the button
            VisualizeButton.IsEnabled = true;
        }
    }
}
