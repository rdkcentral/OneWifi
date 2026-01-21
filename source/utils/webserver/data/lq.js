export function renderLinkQualityChart(data) {
    const lq_params = ["SNR", "PER", "PHY"];
    const leftGridContainer = document.getElementById('LeftGridContainer');

    const existingCharts = leftGridContainer.querySelectorAll('[id^="chart-"]');
    existingCharts.forEach(div => {
        const idx = parseInt(div.id.replace('chart-', ''), 10);
        if (idx >= data.Devices.length) {
            Plotly.purge(div);
            div.parentElement.remove(); // remove wrapper
        }
    });

    for (let i = 0; i < data.Devices.length; i++) {
        const dev = data.Devices[i];
        const chart_data = [];

        const chartId = `chart-${i}`;
        let div = document.getElementById(chartId);
        if (!div) {
            const wrapper = document.createElement('div');
            wrapper.style.width = '100%';
            wrapper.style.background = '#fff';
            wrapper.style.padding = '5px';
            wrapper.style.boxSizing = 'border-box';

            div = document.createElement('div');
            div.id = chartId;
            div.style.height = '400px';
            div.style.width = '100%';

            wrapper.appendChild(div);
            leftGridContainer.appendChild(wrapper);
        }


        for (const key of lq_params) {
            chart_data.push({
                x: dev.Time,
                y: dev.LinkQuality[key],
                type: 'scatter',
                mode: 'lines',
                name: key
            });
        }

        chart_data.push({
            x: dev.Time,
            y: dev.LinkQuality.Score,
            type: 'scatter',
            mode: 'lines',
            name: 'Score',
            line: { width: 2 }
        });

        const alarmX = [];
        const alarmY = [];
        for (let j = 0; j < dev.LinkQuality.Alarms.length; j++) {
            if (dev.LinkQuality.Alarms[j]) {
                alarmX.push(dev.Time[j]);
                alarmY.push(dev.LinkQuality.Score[j]);
            }
        }

        chart_data.push({
            x: alarmX,
            y: alarmY,
            type: 'scatter',
            mode: 'markers',
            name: 'Alarm',
            marker: { color: 'red', size: 10 }
        });

        const layout = {
            title: { text: `Link Quality: ${dev.MAC}`, pad: { t: 25 } },
            margin: { t: 70, l: 40, r: 10, b: 90 },
            xaxis: {
                title: { text: 'Time' },
                type: 'category',
                tickangle: -45,
                tickmode: 'auto',
                automargin: true
            },
            yaxis: {
                title: { text: 'Units' },
                range: [0, 1],
                tick0: 0,
                dtick: 0.1
            }
        };

        Plotly.react(div, chart_data, layout, { responsive: true });
    }
}

function updateAlarmDot(show) {
    const dot = document.getElementById("alarmDot");
    dot.style.display = show ? "inline-block" : "none";
}

export function renderAlarms(data) {
    const table = document.getElementById("Alarms");

    // Reset table header
    table.innerHTML = `
      <tr>
        <th>Device</th>
        <th>Description</th>
        <th>Time</th>
      </tr>`;

    let hasAlarm = false;

    for (const dev of data.Devices) {
        const alarms = dev.LinkQuality?.Alarms || [];

        for (let i = 0; i < alarms.length; i++) {
            if (!alarms[i]) continue;

            hasAlarm = true;

            const row = document.createElement("tr");
            row.innerHTML = `
              <td>${dev.MAC}</td>
              <td>Link Quality Alarm</td>
              <td>${alarms[i]}</td>`;
            table.appendChild(row);
        }
    }

    updateAlarmDot(hasAlarm);
}

