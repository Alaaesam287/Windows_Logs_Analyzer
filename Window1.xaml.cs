using OxyPlot;
using OxyPlot.Series;
using OxyPlot.Axes;
using System.Windows;


namespace Log_Analyzer
{
    public partial class Window1 : Window
    {
        public Window1(List<(DateTime timestamp, double cpuUsage, double memoryUsage)> cpuMemoryData)
        {
            InitializeComponent();

            // Create the plot model
            var plotModel = new PlotModel { Title = "CPU and Memory Usage Over Time" };

            // Configure the time axis (X-axis)
            plotModel.Axes.Add(new DateTimeAxis
            {
                Position = AxisPosition.Bottom,
                Title = "Time",
                StringFormat = "HH:mm",
                Minimum = DateTimeAxis.ToDouble(cpuMemoryData[0].timestamp),
                Maximum = DateTimeAxis.ToDouble(cpuMemoryData[cpuMemoryData.Count - 1].timestamp),
                MajorGridlineStyle = LineStyle.Solid,
                TextColor = OxyColors.Black,
                TitleColor = OxyColors.Black
            });

            // Configure the primary Y-axis (CPU Usage)
            plotModel.Axes.Add(new LinearAxis
            {
                Position = AxisPosition.Left,
                Title = "Usage (%)",
                Minimum = 0,
                Maximum = 100,
                TextColor = OxyColors.Black,
                TitleColor = OxyColors.Black
            });

            // Create the CPU usage series
            var cpuSeries = new LineSeries
            {
                Title = "CPU Usage (%)", // Legend entry
                MarkerType = MarkerType.Circle,
                Color = OxyColors.Red
            };

            // Create the Memory usage series
            var memorySeries = new LineSeries
            {
                Title = "Memory Usage (%)", // Legend entry
                MarkerType = MarkerType.Circle,
                Color = OxyColors.Green
            };

            // Populate the series with data
            foreach (var data in cpuMemoryData)
            {
                cpuSeries.Points.Add(new DataPoint(DateTimeAxis.ToDouble(data.timestamp), data.cpuUsage));
                memorySeries.Points.Add(new DataPoint(DateTimeAxis.ToDouble(data.timestamp), data.memoryUsage));
            }

            // Add the series to the plot model
            plotModel.Series.Add(cpuSeries);
            plotModel.Series.Add(memorySeries);

            // Assign the plot model to the PlotView
            PlotView.Model = plotModel;
        }

    }
}
