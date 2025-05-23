// Ensure Chart.js is included in the HTML file, not here.

// Line Chart
const lineCtx = document.getElementById('lineChart').getContext('2d');
new Chart(lineCtx, {
    type: 'line',
    data: {
        labels: packetData.labels,  // Thời gian (00:00, 01:00, ...)
        datasets: [{
            label: 'Lượng gói tin',
            data: packetData.values,  // Số lượng gói tin theo giờ
            borderColor: '#00aaff',
            backgroundColor: 'rgba(0, 170, 255, 0.2)',
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                display: true
            }
        },
        scales: {
            x: {
                title: {
                    display: true,
                    text: 'Thời gian'
                }
            },
            y: {
                title: {
                    display: true,
                    text: 'Số lượng gói tin'
                },
                beginAtZero: true
            }
        }
    }
  
});

// Pie Chart
const pieCtx = document.getElementById('pieChart').getContext('2d');
const attackLabels = Object.keys(attackData);  // Lấy tên các loại tấn công
const attackValues = Object.values(attackData);  // Lấy số lượng từng loại tấn công

new Chart(pieCtx, {
    type: 'pie',
    data: {
        labels: attackLabels,  // Tên các loại tấn công
        datasets: [{
            label: 'Tấn công',
            data: attackValues,  // Số lượng từng loại tấn công
            backgroundColor: [
                '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'
            ],
            hoverOffset: 4
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                display: true,
                position: 'top'
            }
        }
    }
});

$(document).ready(function () {
    // Hàm cập nhật dữ liệu dashboard
    function updateDashboard() {
        $.ajax({
            url: '/dashboard_data',
            type: 'GET',
            success: function (data) {
                if (data.error) {
                    console.error(data.error);
                    return;
                }

                // Cập nhật tổng gói tin
                $('div.stats-info:contains("Tổng gói tin") p').text(data.total_packets);

                // Cập nhật cuộc tấn công
                $('div.stats-info:contains("Cuộc tấn công") p').text(data.total_attacks);

                // Cập nhật thời gian hoạt động
                $('#uptime').text(data.uptime);
            },
            error: function () {
                console.error("Failed to fetch dashboard data.");
            }
        });
    }

    // Hàm cập nhật biểu đồ số lượng gói tin đặc biệt
    function updateBarChart() {
        $.ajax({
            url: '/monthly_packet_data',
            type: 'GET',
            success: function (data) {
                if (data.error) {
                    console.error(data.error);
                    return;
                }

                const ctx = document.getElementById("barChart").getContext("2d");
                new Chart(ctx, {
                    type: "bar",
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: "Số lượng gói tin đặc biệt",
                            data: data.data,
                            backgroundColor: "rgba(54, 162, 235, 0.6)",
                            borderColor: "rgba(54, 162, 235, 1)",
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            },
            error: function () {
                console.error("Failed to fetch monthly packet data.");
            }
        });
    }

    // Gọi các hàm cập nhật mỗi 5 giây
    function refreshDashboard() {
        updateDashboard();
        updateBarChart();
    }

    refreshDashboard();
    setInterval(refreshDashboard, 100); // Cập nhật mỗi 5 giây
});