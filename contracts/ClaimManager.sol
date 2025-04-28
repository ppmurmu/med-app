// contracts/ClaimManager.sol
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract ClaimManager {
    enum ClaimStatus {
        Requested,
        DoctorApproved,
        Settled
    }

    struct Claim {
        address patient;
        address insurer;
        string recordHash;
        ClaimStatus status;
    }

    Claim[] public claims;
    mapping(address => uint[]) public claimsByInsurer;
    mapping(address => uint[]) public claimsByPatient;

    event ClaimRequested(
        uint indexed id,
        address indexed patient,
        address indexed insurer
    );
    event DoctorApproved(uint indexed id);
    event ClaimSettled(uint indexed id);

    function requestClaim(
        address _insurer,
        string calldata _recordHash
    ) external {
        require(_insurer != address(0), "Bad insurer");
        uint id = claims.length;
        claims.push(
            Claim(msg.sender, _insurer, _recordHash, ClaimStatus.Requested)
        );
        claimsByInsurer[_insurer].push(id);
        claimsByPatient[msg.sender].push(id);
        emit ClaimRequested(id, msg.sender, _insurer);
    }

    function doctorApproveClaim(uint _id) external {
        Claim storage c = claims[_id];
        // TODO: require caller is authorized doctor for c.patient
        c.status = ClaimStatus.DoctorApproved;
        emit DoctorApproved(_id);
    }

    function insurerSettleClaim(uint _id) external payable {
        Claim storage c = claims[_id];
        require(msg.sender == c.insurer, "Only insurer");
        require(c.status == ClaimStatus.DoctorApproved, "Not approved");
        c.status = ClaimStatus.Settled;
        emit ClaimSettled(_id);
    }

    function getClaimsForInsurer() external view returns (uint[] memory) {
        return claimsByInsurer[msg.sender];
    }
    function getClaimsForPatient() external view returns (uint[] memory) {
        return claimsByPatient[msg.sender];
    }
}
