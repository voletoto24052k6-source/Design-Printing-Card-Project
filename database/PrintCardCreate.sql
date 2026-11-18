IF DB_ID(N'PrintCardDB') IS NULL
    CREATE DATABASE PrintCardDB
GO

USE PrintCardDB;
GO

CREATE TABLE PRODUCT_TYPE (
    productID    INT IDENTITY(1,1) CONSTRAINT PK_PRODUCT_TYPE PRIMARY KEY,
    productName  NVARCHAR(100) NOT NULL,
    info         NVARCHAR(500) NULL
);
GO

CREATE TABLE TEMPLATE (
    designID     INT IDENTITY(1,1) CONSTRAINT PK_TEMPLATE PRIMARY KEY,
    designName   NVARCHAR(100) NOT NULL,
    imageUrl     NVARCHAR(300) NULL,
    content      NVARCHAR(MAX) NULL,
    basePrice    DECIMAL(18,0) NOT NULL CONSTRAINT DF_TEMPLATE_price DEFAULT 0,
    info         NVARCHAR(500) NULL,
    productID    INT NOT NULL,
    CONSTRAINT CK_TEMPLATE_price   CHECK (basePrice >= 0),
    CONSTRAINT CK_TEMPLATE_content CHECK (content IS NULL OR ISJSON(content) = 1),
    CONSTRAINT FK_TEMPLATE_PRODUCT_TYPE FOREIGN KEY (productID)
        REFERENCES PRODUCT_TYPE(productID)
);
GO


CREATE TABLE ACCOUNT (
    accountID  INT IDENTITY(1,1) CONSTRAINT PK_ACCOUNT PRIMARY KEY,
    username   VARCHAR(50)   NOT NULL CONSTRAINT UQ_ACCOUNT_username UNIQUE,
    [password] VARCHAR(255)  NOT NULL,      -- lưu mật khẩu đã băm (hash)
    email      VARCHAR(100)  NOT NULL CONSTRAINT UQ_ACCOUNT_email UNIQUE,
    role       VARCHAR(20)   NOT NULL,      -- Admin / Employee / Customer
    isActive   BIT           NOT NULL CONSTRAINT DF_ACCOUNT_isActive DEFAULT 1,   -- 0 = khóa tài khoản
    createdAt  DATETIME2(0)  NOT NULL CONSTRAINT DF_ACCOUNT_createdAt DEFAULT SYSDATETIME(),
    CONSTRAINT CK_ACCOUNT_role  CHECK (role IN ('Admin','Employee','Customer')),
    CONSTRAINT CK_ACCOUNT_email CHECK (email LIKE '%_@_%._%'),
    CONSTRAINT UQ_ACCOUNT_id_role UNIQUE (accountID, role)
);
GO

CREATE TABLE CUSTOMER (
    customerID INT IDENTITY(1,1) CONSTRAINT PK_CUSTOMER PRIMARY KEY,
    accountID  INT           NOT NULL CONSTRAINT UQ_CUSTOMER_account UNIQUE,
    role       VARCHAR(20)   NOT NULL CONSTRAINT DF_CUSTOMER_role DEFAULT 'Customer',
    fullName   NVARCHAR(100) NOT NULL,
    phone      VARCHAR(15)   NULL,
    address    NVARCHAR(300) NULL,
    CONSTRAINT CK_CUSTOMER_role CHECK (role = 'Customer'),
    CONSTRAINT FK_CUSTOMER_ACCOUNT FOREIGN KEY (accountID, role)
        REFERENCES ACCOUNT(accountID, role)
);
GO

CREATE TABLE EMPLOYEE (
    employeeID INT IDENTITY(1,1) CONSTRAINT PK_EMPLOYEE PRIMARY KEY,
    accountID  INT           NOT NULL CONSTRAINT UQ_EMPLOYEE_account UNIQUE,
    role       VARCHAR(20)   NOT NULL CONSTRAINT DF_EMPLOYEE_role DEFAULT 'Employee',
    fullName   NVARCHAR(100) NOT NULL,
    phone      VARCHAR(15)   NOT NULL,
    address    NVARCHAR(255) NULL,
    position   NVARCHAR(50)  NULL,
    hireDate   DATE          NULL,
    CONSTRAINT CK_EMPLOYEE_role CHECK (role = 'Employee'),
    CONSTRAINT FK_EMPLOYEE_ACCOUNT FOREIGN KEY (accountID, role)
        REFERENCES ACCOUNT(accountID, role)
);
GO

CREATE TABLE ADMIN (
    adminID    INT IDENTITY(1,1) CONSTRAINT PK_ADMIN PRIMARY KEY,
    accountID  INT           NOT NULL CONSTRAINT UQ_ADMIN_account UNIQUE,
    role       VARCHAR(20)   NOT NULL CONSTRAINT DF_ADMIN_role DEFAULT 'Admin',
    fullName   NVARCHAR(100) NOT NULL,
    phone      VARCHAR(15)   NULL,
    createdAt  DATETIME2(0)  NOT NULL CONSTRAINT DF_ADMIN_createdAt DEFAULT SYSDATETIME(),
    CONSTRAINT CK_ADMIN_role CHECK (role = 'Admin'),
    CONSTRAINT FK_ADMIN_ACCOUNT FOREIGN KEY (accountID, role)
        REFERENCES ACCOUNT(accountID, role)
);
GO

CREATE TABLE CUSTOM_DESIGN (
    designID       INT IDENTITY(1,1) CONSTRAINT PK_CUSTOM_DESIGN PRIMARY KEY,
    content        NVARCHAR(MAX) NULL,
    imageUrl       NVARCHAR(300) NULL,
    templateID     INT NOT NULL,              -- tham chiếu TEMPLATE.designID
    customerID     INT NOT NULL,
    CONSTRAINT CK_CUSTOM_DESIGN_content CHECK (content IS NULL OR ISJSON(content) = 1),
    CONSTRAINT FK_CUSTOM_DESIGN_TEMPLATE FOREIGN KEY (templateID)
        REFERENCES TEMPLATE(designID),
    CONSTRAINT FK_CUSTOM_DESIGN_CUSTOMER FOREIGN KEY (customerID)
        REFERENCES CUSTOMER(customerID)
);
GO

CREATE TABLE [ORDER] (
    orderID        INT IDENTITY(1,1) CONSTRAINT PK_ORDER PRIMARY KEY,
    orderDate      DATETIME2(0)  NOT NULL CONSTRAINT DF_ORDER_date  DEFAULT SYSDATETIME(),
    address        NVARCHAR(300) NOT NULL,
    state          VARCHAR(20)   NOT NULL CONSTRAINT DF_ORDER_state DEFAULT 'Pending',
    basePrice      DECIMAL(18,0) NOT NULL CONSTRAINT DF_ORDER_price DEFAULT 0,
    customerID     INT           NOT NULL,
    CONSTRAINT CK_ORDER_state CHECK (state IN ('Pending','Processing','Shipping','Delivered','Cancelled')),
    CONSTRAINT CK_ORDER_price CHECK (basePrice >= 0),
    CONSTRAINT FK_ORDER_CUSTOMER FOREIGN KEY (customerID)
        REFERENCES CUSTOMER(customerID)
);
GO

CREATE TABLE ORDER_STATUS_HISTORY (
    historyID    INT IDENTITY(1,1) CONSTRAINT PK_ORDER_STATUS_HISTORY PRIMARY KEY,
    orderID      INT          NOT NULL,
    newState     VARCHAR(20)  NOT NULL,
    changedTime  DATETIME2(0) NOT NULL CONSTRAINT DF_HISTORY_time DEFAULT SYSDATETIME(),
    employeeID   INT          NULL,
    CONSTRAINT CK_HISTORY_state CHECK (newState IN ('Pending','Processing','Shipping','Delivered','Cancelled')),
    CONSTRAINT FK_HISTORY_ORDER FOREIGN KEY (orderID)
        REFERENCES [ORDER](orderID) ON DELETE CASCADE,
    CONSTRAINT FK_HISTORY_EMPLOYEE FOREIGN KEY (employeeID)
        REFERENCES EMPLOYEE(employeeID)
);
GO

CREATE TABLE ORDER_DETAILS (
    orderDetailsID INT IDENTITY(1,1) CONSTRAINT PK_ORDER_DETAILS PRIMARY KEY,
    orderID        INT NOT NULL,
    designID       INT NOT NULL,              -- tham chiếu CUSTOM_DESIGN.designID
    quantity       INT NOT NULL,
    basePrice      DECIMAL(18,0) NOT NULL,    -- đơn giá
    total          AS (quantity * basePrice) PERSISTED,   -- thành tiền (thuộc tính dẫn xuất)
    CONSTRAINT CK_DETAILS_quantity CHECK (quantity > 0),
    CONSTRAINT CK_DETAILS_price    CHECK (basePrice >= 0),
    CONSTRAINT FK_DETAILS_ORDER  FOREIGN KEY (orderID)
        REFERENCES [ORDER](orderID) ON DELETE CASCADE,
    CONSTRAINT FK_DETAILS_DESIGN FOREIGN KEY (designID)
        REFERENCES CUSTOM_DESIGN(designID)
);
GO

CREATE TABLE PAYMENT (
    orderID  INT           NOT NULL CONSTRAINT PK_PAYMENT PRIMARY KEY,
    method   NVARCHAR(50)  NOT NULL,
    state    VARCHAR(20)   NOT NULL CONSTRAINT DF_PAYMENT_state DEFAULT 'Pending',
    time     DATETIME2(0)  NULL,
    total    DECIMAL(18,0) NOT NULL,
    CONSTRAINT CK_PAYMENT_state CHECK (state IN ('Pending','Paid','Failed','Refunded')),
    CONSTRAINT CK_PAYMENT_total CHECK (total >= 0),
    CONSTRAINT FK_PAYMENT_ORDER FOREIGN KEY (orderID)
        REFERENCES [ORDER](orderID) ON DELETE CASCADE
);
GO

CREATE TABLE SHIPMENT (
    orderID  INT           NOT NULL CONSTRAINT PK_SHIPMENT PRIMARY KEY,
    method   NVARCHAR(50)  NOT NULL,
    fee      DECIMAL(18,0) NOT NULL CONSTRAINT DF_SHIPMENT_fee DEFAULT 0,
    CONSTRAINT CK_SHIPMENT_fee CHECK (fee >= 0),
    CONSTRAINT FK_SHIPMENT_ORDER FOREIGN KEY (orderID)
        REFERENCES [ORDER](orderID) ON DELETE CASCADE
);
GO

--   ORDER_DETAILS (1) --review-- (0/1) REVIEW  => mỗi dòng chi tiết có tối đa 1 đánh giá
CREATE TABLE REVIEW (
    orderDetailsID INT          NOT NULL CONSTRAINT PK_REVIEW PRIMARY KEY,
    customerID     INT          NOT NULL,      -- khách viết đánh giá
    design         TINYINT      NOT NULL,      -- điểm thiết kế (1-5)
    quality        TINYINT      NOT NULL,      -- điểm chất lượng in (1-5)
    CONSTRAINT CK_REVIEW_design  CHECK (design  BETWEEN 1 AND 5),
    CONSTRAINT CK_REVIEW_quality CHECK (quality BETWEEN 1 AND 5),
    CONSTRAINT FK_REVIEW_DETAILS  FOREIGN KEY (orderDetailsID)
        REFERENCES ORDER_DETAILS(orderDetailsID) ON DELETE CASCADE,
    CONSTRAINT FK_REVIEW_CUSTOMER FOREIGN KEY (customerID)
        REFERENCES CUSTOMER(customerID)
);
GO

CREATE INDEX IX_TEMPLATE_product        ON TEMPLATE(productID);
CREATE INDEX IX_CUSTOM_DESIGN_template  ON CUSTOM_DESIGN(templateID);
CREATE INDEX IX_CUSTOM_DESIGN_customer  ON CUSTOM_DESIGN(customerID);
CREATE INDEX IX_ORDER_customer          ON [ORDER](customerID);
CREATE INDEX IX_ORDER_state             ON [ORDER](state);
CREATE INDEX IX_HISTORY_order           ON ORDER_STATUS_HISTORY(orderID);
CREATE INDEX IX_HISTORY_employee        ON ORDER_STATUS_HISTORY(employeeID);
CREATE INDEX IX_DETAILS_order           ON ORDER_DETAILS(orderID);
CREATE INDEX IX_DETAILS_design          ON ORDER_DETAILS(designID);
CREATE INDEX IX_REVIEW_customer         ON REVIEW(customerID);
GO