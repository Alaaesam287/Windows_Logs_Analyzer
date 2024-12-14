using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Collections.Generic;
using System.Threading.Tasks;
using OxyPlot;
using OxyPlot.Series;
using OxyPlot.Axes;
using OxyPlot.WindowsForms;
using Microsoft.Win32;

namespace WindowsLogsAnalyzer
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

                    var cpuMemoryData = GetCpuMemoryUsage(startDate, endDate);

                    CustomizeAndExportLogs(logEntries, suspiciousLogs, cpuMemoryData, startDate, endDate);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred while fetching logs: " + ex.Message);
            }
        }

        private bool IsSuspiciousLog(EventLogEntry entry)
        {
            string[] suspiciousKeywords = { "error", "failed", "unauthorized", "critical", "malware", "attack", "denied" };
            EventLogEntryType[] suspiciousTypes = { EventLogEntryType.Error, EventLogEntryType.FailureAudit };

            return suspiciousKeywords.Any(keyword => entry.Message.Contains(keyword, StringComparison.OrdinalIgnoreCase)) ||
                   suspiciousTypes.Contains(entry.EntryType);
        }

        private List<(DateTime timestamp, double cpuUsage, double memoryUsage)> GetCpuMemoryUsage(DateTime startDate, DateTime endDate)
        {
            var data = new List<(DateTime timestamp, double cpuUsage, double memoryUsage)>();

            Random rand = new Random();
            DateTime currentTime = startDate;
            while (currentTime <= endDate)
            {
                data.Add((currentTime, rand.NextDouble() * 100, rand.NextDouble() * 100));
                currentTime = currentTime.AddMinutes(1);
            }

            return data;
        }

        private void CustomizeAndExportLogs(
            List<EventLogEntry> allLogs,
            List<EventLogEntry> suspiciousLogs,
            List<(DateTime timestamp, double cpuUsage, double memoryUsage)> cpuMemoryData,
            DateTime startDate,
            DateTime endDate)
        {
            // First SaveFileDialog for logs
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

                    // Second SaveFileDialog for PNG
                    SaveFileDialog pngSaveDialog = new SaveFileDialog
                    {
                        Title = "Save CPU/Memory Usage as PNG",
                        Filter = "PNG Files (*.png)|*.png",
                        DefaultExt = "png",
                        FileName = $"CpuMemoryUsage_{startDate:yyyyMMdd}_{endDate:yyyyMMdd}.png"
                    };

                    if (pngSaveDialog.ShowDialog() == true)
                    {
                        string pngFilePath = pngSaveDialog.FileName;

                        // Export CPU and Memory usage to PNG
                        ExportCpuMemoryUsageToPng(pngFilePath, cpuMemoryData, startDate, endDate);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error during export: " + ex.Message);
                }
            }
        }

        private async void ExportCpuMemoryUsageToPng(string filePath, List<(DateTime timestamp, double cpuUsage, double memoryUsage)> cpuMemoryData, DateTime startDate, DateTime endDate)
        {
            try
            {
                var plotModel = new PlotModel
                {
                    Title = "CPU and Memory Usage Over Time",
                    PlotAreaBackground = OxyColors.White,
                    TextColor = OxyColors.White,  // Set axis text color to white
                    TitleColor = OxyColors.White // Set axis title color to white
                };

                plotModel.Axes.Add(new DateTimeAxis
                {
                    Position = AxisPosition.Bottom,
                    Title = "Time",
                    StringFormat = "HH:mm",
                    Minimum = DateTimeAxis.ToDouble(startDate),
                    Maximum = DateTimeAxis.ToDouble(endDate),
                    TextColor = OxyColors.White,  // Set axis text color to white
                    TitleColor = OxyColors.White // Set axis title color to white

                });

                plotModel.Axes.Add(new LinearAxis
                {
                    Position = AxisPosition.Left,
                    Title = "Usage (%)",
                    Minimum = 0,
                    Maximum = 100,
                    TextColor = OxyColors.White,  // Set axis text color to white
                    TitleColor = OxyColors.White // Set axis title color to white

                });

                var cpuSeries = new LineSeries { Title = "CPU Usage (%)", MarkerType = MarkerType.Circle, Color = OxyColors.Red };
                var memorySeries = new LineSeries { Title = "Memory Usage (%)", MarkerType = MarkerType.Circle, Color = OxyColors.Green };

                foreach (var data in cpuMemoryData)
                {
                    cpuSeries.Points.Add(new DataPoint(DateTimeAxis.ToDouble(data.timestamp), data.cpuUsage));
                    memorySeries.Points.Add(new DataPoint(DateTimeAxis.ToDouble(data.timestamp), data.memoryUsage));
                }

                plotModel.Series.Add(cpuSeries);
                plotModel.Series.Add(memorySeries);

                var exporter = new PngExporter { Width = 2000, Height = 800 };

                await Task.Run(() => exporter.ExportToFile(plotModel, filePath));

            }
            catch (Exception ex)
            {
                MessageBox.Show("Error exporting data to PNG: " + ex.Message);
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
    }
}
