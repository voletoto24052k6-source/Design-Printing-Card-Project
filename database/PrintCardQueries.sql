USE PrintCardDB;
GO

-- Doanh thu theo trạng thái đơn
SELECT state, COUNT(*) AS so_don, SUM(basePrice) AS tong_tien
FROM [ORDER] GROUP BY state ORDER BY so_don DESC;

-- Mẫu được đặt nhiều nhất
SELECT TOP 5 t.designName, SUM(d.quantity) AS so_luong
FROM ORDER_DETAILS d
JOIN CUSTOM_DESIGN cd ON cd.designID = d.designID
JOIN TEMPLATE t ON t.designID = cd.templateID
JOIN [ORDER] o ON o.orderID = d.orderID AND o.state <> 'Cancelled'
GROUP BY t.designName ORDER BY so_luong DESC;
GO