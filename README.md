# Inventory-Management-Application

# WebApp Deployment and Dependencies Documentation

This documentation provides a step-by-step guide on how to deploy the given web application on a server, along with the necessary dependencies and configurations.

## Table of Contents
1. [Introduction](#introduction)
2. [Dependencies](#dependencies)
3. [SQL Server Table Creation](#sql-server-setup)
4. [Deployment Steps](#deployment-steps)

## 1. Introduction<a name="introduction"></a>
This web application is built using Flask and relies on various libraries and dependencies to function properly. The application includes multiple files, including Flask code, SQL handling scripts, and HTML templates.

## 2. Python Dependencies<a name="dependencies"></a>
Before deploying the web application, make sure you have the following dependencies installed:

- Python (3.6+)
- Flask
- pyodbc
- requests
- aspose.pdf
- reportlab
- flask_session

You can install these dependencies using the following command:
```bash
pip install Flask pyodbc requests aspose.pdf reportlab flask_session
```

## 3. SQL Server Setup<a name="sql-server-setup"></a>
Before running the web application, ensure that you have a Microsoft SQL Server instance configured and running. Update the connection string in the code to match your SQL Server configuration. Modify the connection string in  `sqlhandle.py`.

## Tables Creation
Create the required tables in your SQL Server database. Execute the following SQL queries to create the necessary tables:


1. **Finished Product Table**:

   ```sql
   CREATE TABLE FINISHEDPRODUCT (
    CODE NVARCHAR(50) PRIMARY KEY,
    PRODUCTNAME NVARCHAR(255) NOT NULL UNIQUE,
    COST FLOAT NOT NULL,
    UNIT NVARCHAR(50) NOT NULL,
    QUANTITY INT NOT NULL,
    PRICE FLOAT NOT NULL,
    REMOVED CHAR(1) NOT NULL
   );
   
   -- Reset identity seed for FINISHEDPRODUCT table
   DBCC CHECKIDENT ('FINISHEDPRODUCT', RESEED, 0);
   ```

  2. **Raw Materials Table**:

   ```sql
   CREATE TABLE RAWMATERIALS (
    MATERIALID INT PRIMARY KEY IDENTITY(1,1),
    NAME NVARCHAR(255) NOT NULL UNIQUE,
    COST FLOAT NOT NULL,
    UNITS NVARCHAR(50) NOT NULL,
    QUANTITY INT NOT NULL,
    ASSOCIATED_CODES NVARCHAR(MAX) NOT NULL,
    REMOVED CHAR(1) NOT NULL
);


   -- Reset identity seed for RAWMATERIALS table
   DBCC CHECKIDENT ('RAWMATERIALS', RESEED, 0);
    ```

3. **Packaging Materials Table**:

   ```sql
   CREATE TABLE PACKAGINGMATERIALS (
    MATERIALID INT PRIMARY KEY IDENTITY(1,1),
    NAME NVARCHAR(255) NOT NULL UNIQUE,
    COST FLOAT NOT NULL,
    QUANTITY INT NOT NULL,
    ASSOCIATED_CODES NVARCHAR(MAX) NOT NULL,
    REMOVED CHAR(1) NOT NULL
);


   -- Reset identity seed for PACKAGINGMATERIALS table
   DBCC CHECKIDENT ('PACKAGINGMATERIALS', RESEED, 0);
    ```

4. **RAWMATERIALASSOCIATION Table**:

   ```sql
   CREATE TABLE RAWMATERIALASSOCIATION (
    ASSOCIATIONID INT PRIMARY KEY IDENTITY(1,1),
    RAWMATERIALID INT NOT NULL,
    CODE NVARCHAR(50) NOT NULL,
    FOREIGN KEY (RAWMATERIALID) REFERENCES RAWMATERIALS (MATERIALID),
    FOREIGN KEY (CODE) REFERENCES FinishedProduct (CODE)
);


   -- Reset identity seed for RAWMATERIALASSOCIATION table
   DBCC CHECKIDENT ('RAWMATERIALASSOCIATION', RESEED, 0);
    ```

5. **PACKAGINGMATERIALASSOCIATION Table**:

   ```sql
   CREATE TABLE PACKAGINGMATERIALASSOCIATION (
    ASSOCIATIONID INT PRIMARY KEY IDENTITY(1,1),
    PACKAGINGMATERIALID INT NOT NULL,
    CODE NVARCHAR(50) NOT NULL,
    FOREIGN KEY (PACKAGINGMATERIALID) REFERENCES PACKAGINGMATERIALS (MATERIALID),
    FOREIGN KEY (CODE) REFERENCES FinishedProduct (CODE)
);


   -- Reset identity seed for PACKAGINGMATERIALASSOCIATION table
   DBCC CHECKIDENT ('PACKAGINGMATERIALASSOCIATION', RESEED, 0);
    ```

6. **USERS Table**:

   ```sql
   CREATE TABLE USERS (
    ID INT PRIMARY KEY IDENTITY(1,1),
    USERNAME NVARCHAR(255) NOT NULL UNIQUE,
    PASSWORD NVARCHAR(255) NOT NULL,
    PRIVEILEGE NVARCHAR(255) NOT NULL,
    REMOVED CHAR(1) NOT NULL
);


   -- Reset identity seed for USERS table
   DBCC CHECKIDENT ('USERS', RESEED, 0);
    ```

7. **UNITS_RM Table**:

   ```sql
   CREATE TABLE UNITS_RM (
    UNITID INT PRIMARY KEY IDENTITY(1,1),
    NAME NVARCHAR(255) NOT NULL UNIQUE,
    REMOVED CHAR(1) NOT NULL
);


   -- Reset identity seed for UNITS_RM table
   DBCC CHECKIDENT ('UNITS_RM', RESEED, 0);
    ```

8. **UNITS_FP Table**:

   ```sql
   CREATE TABLE UNITS_FP (
    UNITID INT PRIMARY KEY IDENTITY(1,1),
    NAME NVARCHAR(255) NOT NULL UNIQUE,
    REMOVED CHAR(1) NOT NULL
);


   -- Reset identity seed for UNITS_FP table
   DBCC CHECKIDENT ('UNITS_FP', RESEED, 0);
    ```

9. **CUSTOMERS Table**:

   ```sql
   CREATE TABLE CUSTOMERS (
    CUSTOMERID INT PRIMARY KEY IDENTITY(1,1),
    CONTACT_NAME NVARCHAR(255) NOT NULL UNIQUE,
    COMPANY_NAME NVARCHAR(255) NOT NULL UNIQUE,
    PHONE_NUMBER NVARCHAR(255) NOT NULL UNIQUE,
    EMAIL_ADDRESS NVARCHAR(255) NOT NULL UNIQUE,
    SHIPPING_ADDRESS NVARCHAR(255) NOT NULL,
    REMOVED CHAR(1) NOT NULL
);

10. **WORK_ORDERS_INFO Table**:

   ```sql
   CREATE TABLE WORK_ORDERS_INFO (
    WORK_ORDER_ID INT PRIMARY KEY IDENTITY(1,1),
    CONTACT_NAME NVARCHAR(255) NOT NULL,
    CREATED_ON NVARCHAR(255) NOT NULL,
    DUE_BY NVARCHAR(255) NOT NULL,
    STATUS NVARCHAR(255) NOT NULL
);



   -- Reset identity seed for WORK_ORDERS_INFO table
   DBCC CHECKIDENT ('WORK_ORDERS_INFO', RESEED, 0);
    ```

## 4. Deployment Steps<a name="deployment-steps"></a>
Follow these steps to deploy the web application:

1. **Clone the Repository**: Clone the repository or transfer the necessary files to your server.

2. **Navigate to Root Directory**: Open a terminal on the server and navigate to the root directory of the web application.

3. **Install Dependencies**: Install the required dependencies as mentioned in the "Dependencies" section.

4. **Start the program**: While in the root directory of the web application run ```python main.py```
