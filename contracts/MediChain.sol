// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "./ClaimManager.sol";

contract MediChain is ClaimManager {
    // State Variables
    string public name;
    uint public transactionCount;
    address[] public patientList;
    address[] public doctorList;
    address[] public insurerList;

    uint8 constant DESIGNATION_INSURER = 3;

    struct Event {
        address actor;
        string action;
        uint timestamp;
    }

    struct Patient {
        string name;
        string email;
        uint age;
        bool exists;
        bool policyActive;
        uint[] transactions;
        address[] doctorAccessList;
        Event[] medicalEvents;
        string[] medicalRecords;
    }

    struct Doctor {
        string name;
        string email;
        bool exists;
        uint[] transactions;
        address[] patientAccessList;
    }

    struct Insurer {
        string name;
        string email;
        bool exists;
    }

    mapping(address => Patient) public patientInfo;
    mapping(address => Doctor) public doctorInfo;
    mapping(address => Insurer) public insurers;

    mapping(string => address) public emailToAddress;
    mapping(string => uint) public emailToDesignation;

    struct Transactions {
        uint id;
        address sender;
        address receiver;
        uint value;
        bool settled;
    }
    mapping(uint => Transactions) public transactions;
    uint[] public transactionIds;

    // Events for patient/doctor/insurer registrations & medical-record ops
    event PatientRegistered(
        address indexed patient,
        string email,
        uint designation
    );
    event DoctorRegistered(address indexed doctor, string email);
    event InsurerRegistered(address indexed insurer, string email);
    event MedicalRecordUpdated(
        address indexed patient,
        string ipfsHash,
        uint timestamp
    );
    event MedicalRecordDeleted(
        address indexed patient,
        uint index,
        uint timestamp
    );
    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);

    constructor() {
        name = "MediChain";
        transactionCount = 0;
    }

    function register(
        string memory _name,
        uint _age,
        uint _designation,
        string memory _email,
        string memory _ipfsHash
    ) public {
        require(msg.sender != address(0), "Invalid address");
        require(bytes(_name).length > 0, "Name is required");
        require(bytes(_email).length > 0, "Email is required");
        require(emailToAddress[_email] == address(0), "Email already used");
        require(emailToDesignation[_email] == 0, "Designation already set");

        address _addr = msg.sender;
        require(!patientInfo[_addr].exists, "Already patient");
        require(!doctorInfo[_addr].exists, "Already doctor");
        require(!insurers[_addr].exists, "Already insurer");

        if (_designation == 1) {
            // Patient logic…
            require(_age > 0, "Age > 0");
            require(bytes(_ipfsHash).length > 0, "IPFS hash required");

            Patient storage p = patientInfo[_addr];
            p.name = _name;
            p.email = _email;
            p.age = _age;
            p.exists = true;
            p.medicalRecords.push(_ipfsHash);
            p.medicalEvents.push(Event(_addr, "register", block.timestamp));
            patientList.push(_addr);

            emailToAddress[_email] = _addr;
            emailToDesignation[_email] = _designation;
            emit PatientRegistered(_addr, _email, _designation);
        } else if (_designation == 2) {
            // Doctor logic…
            Doctor storage d = doctorInfo[_addr];
            d.name = _name;
            d.email = _email;
            d.exists = true;
            doctorList.push(_addr);

            emailToAddress[_email] = _addr;
            emailToDesignation[_email] = _designation;
            emit DoctorRegistered(_addr, _email);
        } else if (_designation == DESIGNATION_INSURER) {
            // Insurer logic…
            Insurer storage i = insurers[_addr];
            i.name = _name;
            i.email = _email;
            i.exists = true;
            insurerList.push(_addr);

            emailToAddress[_email] = _addr;
            emailToDesignation[_email] = _designation;
            emit InsurerRegistered(_addr, _email);
        } else {
            revert("Invalid designation");
        }
    }

    // Expose insurer info
    function getInsurerInfo(
        address _insurer
    ) external view returns (string memory, string memory, bool) {
        Insurer storage i = insurers[_insurer];
        return (i.name, i.email, i.exists);
    }

    /// @notice Return all registered insurer addresses
    function getAllInsurers() external view returns (address[] memory) {
        return insurerList;
    }

    // All your existing medical‐record, access, transaction, audit, etc. functions go here…
    // They remain exactly as before.

    // Create or update the medical record
    function createOrUpdateMedicalRecord(
        address _patient,
        string memory _ipfsHash
    ) external {
        require(
            doctorInfo[msg.sender].exists,
            "Only registered doctors can create/update medical records"
        );
        require(patientInfo[_patient].exists, "Patient is not registered");
        require(
            isDoctorAuthorized(_patient, msg.sender),
            "Doctor not authorized for this patient"
        );

        // Update the medical record of the patient (versioning)
        patientInfo[_patient].medicalRecords.push(_ipfsHash);
        // Add event for auditing
        patientInfo[_patient].medicalEvents.push(
            Event(msg.sender, "create/update record", block.timestamp)
        );

        emit MedicalRecordUpdated(_patient, _ipfsHash, block.timestamp);
    }

    // Delete a medical record
    function deleteMedicalRecord(address _patient, uint _index) public {
        require(patientInfo[_patient].exists, "Patient does not exist");
        // Only the patient or authorized doctor can delete
        require(
            msg.sender == _patient || isDoctorAuthorized(_patient, msg.sender),
            "Not authorized to delete records"
        );
        uint length = patientInfo[_patient].medicalRecords.length;
        require(_index < length, "Index out of bounds");

        // Remove the record at _index by shifting and popping
        for (uint i = _index; i < length - 1; i++) {
            patientInfo[_patient].medicalRecords[i] = patientInfo[_patient]
                .medicalRecords[i + 1];
        }
        patientInfo[_patient].medicalRecords.pop();

        // Add event for auditing
        patientInfo[_patient].medicalEvents.push(
            Event(msg.sender, "delete record", block.timestamp)
        );

        emit MedicalRecordDeleted(_patient, _index, block.timestamp);
    }

    // Grant access to a doctor for a patient's medical record
    function grantAccessToDoctor(address _doctor) external {
        require(patientInfo[msg.sender].exists, "Patient not registered");
        require(doctorInfo[_doctor].exists, "Doctor not registered");
        require(
            !isDoctorAuthorized(msg.sender, _doctor),
            "Doctor already has access"
        );

        // Add doctor to the patient's access list
        patientInfo[msg.sender].doctorAccessList.push(_doctor);
        doctorInfo[_doctor].patientAccessList.push(msg.sender);
        string memory action = string.concat(
            "grant access to ",
            doctorInfo[_doctor].name
        );
        patientInfo[msg.sender].medicalEvents.push(
            Event(msg.sender, action, block.timestamp)
        );

        emit AccessGranted(msg.sender, _doctor);
    }

    // Revoke access from a doctor
    function revokeAccessToDoctor(address _doctor) external {
        require(patientInfo[msg.sender].exists, "Patient not registered");
        require(doctorInfo[_doctor].exists, "Doctor not registered");
        require(
            isDoctorAuthorized(msg.sender, _doctor),
            "Doctor does not have access"
        );

        // Remove doctor from the access list
        removeFromList(patientInfo[msg.sender].doctorAccessList, _doctor);
        removeFromList(doctorInfo[_doctor].patientAccessList, msg.sender);

        string memory action = string.concat(
            "remove access to ",
            doctorInfo[_doctor].name
        );
        patientInfo[msg.sender].medicalEvents.push(
            Event(msg.sender, action, block.timestamp)
        );

        emit AccessRevoked(msg.sender, _doctor);
    }

    // Create a transaction and store its ID
    function createTransaction(address _receiver, uint _value) public {
        require(
            msg.sender != _receiver,
            "Sender and receiver must be different"
        );

        transactionCount++;
        Transactions memory newTxn = Transactions({
            id: transactionCount,
            sender: msg.sender,
            receiver: _receiver,
            value: _value,
            settled: false
        });

        transactions[transactionCount] = newTxn;
        transactionIds.push(transactionCount); // Add transaction ID to list

        Patient storage pinfo = patientInfo[msg.sender];
        pinfo.transactions.push(transactionCount);
        Doctor storage dinfo = doctorInfo[_receiver];
        dinfo.transactions.push(transactionCount);
    }

    // Settle a transaction (update status)
    function settleTransaction(uint _transactionId) public {
        Transactions storage txn = transactions[_transactionId];
        require(
            msg.sender == txn.sender || msg.sender == txn.receiver,
            "Not authorized to settle this transaction"
        );
        txn.settled = true;
    }

    // Get all transactions related to a specific address
    function getTransactionsForAddress(
        address _addr
    ) public view returns (Transactions[] memory) {
        if (patientInfo[_addr].exists) {
            uint[] memory txnIds = patientInfo[_addr].transactions;
            Transactions[] memory result = new Transactions[](txnIds.length);
            for (uint i = 0; i < txnIds.length; i++) {
                result[i] = transactions[txnIds[i]];
            }
            return result;
        } else if (doctorInfo[_addr].exists) {
            uint[] memory txnIds = doctorInfo[_addr].transactions;
            Transactions[] memory result = new Transactions[](txnIds.length);
            for (uint i = 0; i < txnIds.length; i++) {
                result[i] = transactions[txnIds[i]];
            }
            return result;
        } else {
            return new Transactions[](0);
        }
    }

    // Get audit history of patient records
    function getPatientAuditHistory(
        address _addr
    ) public view returns (Event[] memory) {
        require(_addr != address(0), "Invalid address");
        require(patientInfo[_addr].exists, "Patient does not exist");
        return patientInfo[_addr].medicalEvents;
    }

    // Get all medical records of a patient
    function getMedicalRecords(
        address _addr
    ) public view returns (string[] memory) {
        require(patientInfo[_addr].exists, "Patient does not exist");
        return patientInfo[_addr].medicalRecords;
    }

    // Get patient access list
    function getPatientAccessList(
        address _patient
    ) public view returns (address[] memory) {
        require(patientInfo[_patient].exists, "Patient does not exist");
        return patientInfo[_patient].doctorAccessList;
    }

    // Get doctor access list
    function getDoctorAccessList(
        address _doctor
    ) public view returns (address[] memory) {
        require(doctorInfo[_doctor].exists, "Doctor does not exist");
        return doctorInfo[_doctor].patientAccessList;
    }

    // Get all doctors
    function getAllDoctors() public view returns (address[] memory) {
        return doctorList;
    }

    // Internal function to check if a doctor is authorized for a patient
    function isDoctorAuthorized(
        address _patient,
        address _doctor
    ) internal view returns (bool) {
        address[] memory accessList = patientInfo[_patient].doctorAccessList;
        for (uint i = 0; i < accessList.length; i++) {
            if (accessList[i] == _doctor) {
                return true;
            }
        }
        return false;
    }

    // Internal function to remove an address from a list
    function removeFromList(address[] storage Array, address addr) internal {
        require(addr != address(0), "Invalid address");
        bool found = false;
        uint index = 0;

        for (uint i = 0; i < Array.length; i++) {
            if (Array[i] == addr) {
                found = true;
                index = i;
                break;
            }
        }

        require(found, "Address not found in the list");

        if (index < Array.length - 1) {
            Array[index] = Array[Array.length - 1];
        }
        Array.pop();
    }

    // Get the length of the patient list
    function getPatientListLength() public view returns (uint) {
        return patientList.length;
    }

    // Get the length of the doctor list
    function getDoctorListLength() public view returns (uint) {
        return doctorList.length;
    }

    // Get Doctor Information
    function getDoctorInfo(
        address _doctor
    )
        public
        view
        returns (
            string memory,
            string memory,
            bool,
            uint[] memory,
            address[] memory
        )
    {
        Doctor storage d = doctorInfo[_doctor];
        return (d.name, d.email, d.exists, d.transactions, d.patientAccessList);
    }

    // Get Patient Basic Information
    function getPatientBasicInfo(
        address _patient
    ) public view returns (string memory, string memory, uint, bool, bool) {
        Patient storage p = patientInfo[_patient];
        return (p.name, p.email, p.age, p.exists, p.policyActive);
    }

    // Get Patient Events Count
    function getPatientEventsCount(
        address _patient
    ) public view returns (uint) {
        return patientInfo[_patient].medicalEvents.length;
    }

    // Get a specific Patient Event by index
    function getPatientEvent(
        address _patient,
        uint index
    ) public view returns (address, string memory, uint) {
        Event storage evt = patientInfo[_patient].medicalEvents[index];
        return (evt.actor, evt.action, evt.timestamp);
    }

    //-------------TRANSFER PATIENT FEATURE----------
    /// Emit whenever a patient is reassigned from one doctor to another
    event PatientTransferred(
        address indexed patient,
        address indexed fromDoctor,
        address indexed toDoctor,
        uint256 timestamp
    );

    function transferPatientFromDoctor(
        address patient,
        address toDoctor
    ) external {
        // 1. Only a registered doctor who already has access to that patient can call
        require(doctorInfo[msg.sender].exists, "Only doctors can transfer");
        require(patientInfo[patient].exists, "Patient not registered");
        require(
            isDoctorAuthorized(patient, msg.sender),
            "Not authorized for this patient"
        );

        // 2. The target doctor must be registered
        require(doctorInfo[toDoctor].exists, "New doctor not registered");

        // 3. Revoke old doctor’s access
        removeFromList(patientInfo[patient].doctorAccessList, msg.sender);
        removeFromList(doctorInfo[msg.sender].patientAccessList, patient);

        // 4. Grant new doctor’s access
        patientInfo[patient].doctorAccessList.push(toDoctor);
        doctorInfo[toDoctor].patientAccessList.push(patient);

        string memory action = string.concat(
            "report transferred to ",
            doctorInfo[toDoctor].name
        );
        patientInfo[patient].medicalEvents.push(
            Event(msg.sender, action, block.timestamp)
        );

        // 5. Emit audit event
        emit PatientTransferred(patient, msg.sender, toDoctor, block.timestamp);
    }
}
