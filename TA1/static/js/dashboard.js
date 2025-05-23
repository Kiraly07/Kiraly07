$(document).ready(function () {
    $('#start-btn').click(function () {
        $.ajax({
            url: '/start_ids',
            type: 'POST',
            success: function (data) {
                if (data.status === 'started') {
                    $('#status').text('IDS started successfully!').removeClass('text-danger').addClass('text-success');
                } else {
                    $('#status').text('IDS is already running.').removeClass('text-success').addClass('text-warning');
                }
            },
            error: function () {
                $('#status').text('Failed to start IDS. Please try again.').removeClass('text-success').addClass('text-danger');
            }
        });
    });

    $('#stop-btn').click(function () {
        $.ajax({
            url: '/stop_ids',
            type: 'POST',
            success: function (data) {
                if (data.status === 'stopped') {
                    $('#status').text('IDS stopped successfully!').removeClass('text-danger').addClass('text-success');
                } else {
                    $('#status').text('IDS is not running.').removeClass('text-success').addClass('text-warning');
                }
            },
            error: function () {
                $('#status').text('Failed to stop IDS. Please try again.').removeClass('text-success').addClass('text-danger');
            }
        });
    });
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

                // Xóa logic liên quan đến "Phân tích tấn công"
                // (Không cần cập nhật dữ liệu cho biểu đồ đã bị xóa)
            },
            error: function () {
                console.error("Failed to fetch dashboard data.");
            }
        });
    }

    // Gọi hàm cập nhật mỗi 5 giây
    updateDashboard();
    setInterval(updateDashboard, 100);
});