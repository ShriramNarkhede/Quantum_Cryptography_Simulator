"""
Eve (Eavesdropper) Attack Simulation Module
Implements various quantum attacks on BB84 protocol
"""

import random
import logging
from typing import List, Dict, Any, Optional
from qiskit import QuantumCircuit, ClassicalRegister
from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator

logger = logging.getLogger(__name__)


class EveModule:
    """Eve attack simulation module"""
    
    def __init__(self):
        self.simulator = AerSimulator()
        self.attack_log: List[Dict[str, Any]] = []
        logger.info("Eve Module initialized")
    
    def apply_attack(self, qubits_data: List[Dict[str, Any]], 
                    eve_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Apply Eve's attack to transmitted qubits
        
        Args:
            qubits_data: List of qubit information from Alice
            eve_params: Attack parameters including type and configuration
            
        Returns:
            Modified qubits_data after Eve's attack
        """
        if not eve_params:
            return qubits_data
        
        attack_type = eve_params.get("attack_type", "none")
        attack_params = eve_params.get("params", {})
        
        logger.info(f"Eve applying {attack_type} attack with params: {attack_params}")
        
        if attack_type == "intercept_resend":
            return self._intercept_resend_attack(qubits_data, attack_params)
        elif attack_type == "partial_intercept":
            return self._partial_intercept_attack(qubits_data, attack_params)
        elif attack_type == "depolarizing":
            return self._depolarizing_attack(qubits_data, attack_params)
        elif attack_type == "qubit_loss":
            return self._qubit_loss_attack(qubits_data, attack_params)
        else:
            logger.warning(f"Unknown attack type: {attack_type}")
            return qubits_data
    
    def _intercept_resend_attack(self, qubits_data: List[Dict[str, Any]], 
                                params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Intercept-and-resend attack: Eve measures qubits and resends new ones
        This is the classic BB84 attack that introduces 25% error rate when bases don't match
        """
        fraction = params.get("fraction", 1.0)  # Fraction of qubits to attack
        eve_basis_strategy = params.get("basis_strategy", "random")  # random, alice, or fixed
        
        attacked_qubits = []
        attack_count = 0
        
        for i, qubit_data in enumerate(qubits_data):
            if random.random() < fraction:  # Attack this qubit
                attack_count += 1
                
                # Eve chooses measurement basis
                if eve_basis_strategy == "random":
                    eve_basis = random.randint(0, 1)
                elif eve_basis_strategy == "alice":
                    eve_basis = qubit_data["alice_basis"]  # Perfect knowledge (unrealistic)
                else:  # fixed basis
                    eve_basis = 0  # Always use Z basis
                
                # Eve measures the qubit
                measured_bit = self._measure_qubit(qubit_data["quantum_circuit"], eve_basis)
                
                # Eve prepares and sends new qubit based on measurement
                new_qubit_data = self._prepare_new_qubit(measured_bit, eve_basis, qubit_data)
                
                # Log attack
                self.attack_log.append({
                    "qubit_index": i,
                    "attack_type": "intercept_resend",
                    "eve_basis": eve_basis,
                    "measured_bit": measured_bit,
                    "alice_bit": qubit_data["alice_bit"],
                    "alice_basis": qubit_data["alice_basis"]
                })
                
                attacked_qubits.append(new_qubit_data)
            else:
                # Pass through unmodified
                attacked_qubits.append(qubit_data)
        
        logger.info(f"Intercept-resend attack: {attack_count}/{len(qubits_data)} qubits attacked")
        return attacked_qubits
    
    def _partial_intercept_attack(self, qubits_data: List[Dict[str, Any]], 
                                 params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Partial intercept attack: Eve only attacks a fraction of qubits
        Similar to intercept-resend but with configurable fraction
        """
        fraction = params.get("fraction", 0.5)
        eve_basis = params.get("eve_basis", 0)  # 0 for Z, 1 for X
        
        return self._intercept_resend_attack(qubits_data, {
            "fraction": fraction,
            "basis_strategy": "fixed" if eve_basis is not None else "random"
        })
    
    def _depolarizing_attack(self, qubits_data: List[Dict[str, Any]], 
                           params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Depolarizing noise attack: Introduces random bit flips
        Simulates noisy quantum channel or sophisticated Eve attack
        """
        noise_probability = params.get("noise_probability", 0.1)
        
        attacked_qubits = []
        noise_count = 0
        
        for i, qubit_data in enumerate(qubits_data):
            if random.random() < noise_probability:
                noise_count += 1
                
                # Apply random Pauli operation (bit flip, phase flip, or both)
                noise_type = random.choice(["X", "Z", "Y"])
                new_qubit_data = self._apply_pauli_noise(qubit_data, noise_type)
                
                # Log attack
                self.attack_log.append({
                    "qubit_index": i,
                    "attack_type": "depolarizing",
                    "noise_type": noise_type,
                    "alice_bit": qubit_data["alice_bit"],
                    "alice_basis": qubit_data["alice_basis"]
                })
                
                attacked_qubits.append(new_qubit_data)
            else:
                attacked_qubits.append(qubit_data)
        
        logger.info(f"Depolarizing attack: {noise_count}/{len(qubits_data)} qubits affected")
        return attacked_qubits
    
    def _qubit_loss_attack(self, qubits_data: List[Dict[str, Any]], 
                          params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Qubit loss attack: Eve drops some qubits entirely
        Simulates lossy quantum channel or selective jamming
        """
        loss_probability = params.get("loss_probability", 0.1)
        
        surviving_qubits = []
        lost_count = 0
        
        for i, qubit_data in enumerate(qubits_data):
            if random.random() < loss_probability:
                lost_count += 1
                
                # Log loss
                self.attack_log.append({
                    "qubit_index": i,
                    "attack_type": "qubit_loss",
                    "alice_bit": qubit_data["alice_bit"],
                    "alice_basis": qubit_data["alice_basis"]
                })
                
                # Mark qubit as lost (Bob will get random measurement)
                lost_qubit_data = qubit_data.copy()
                lost_qubit_data["lost"] = True
                surviving_qubits.append(lost_qubit_data)
            else:
                surviving_qubits.append(qubit_data)
        
        logger.info(f"Qubit loss attack: {lost_count}/{len(qubits_data)} qubits lost")
        return surviving_qubits
    
    def _measure_qubit(self, quantum_circuit: QuantumCircuit, eve_basis: int) -> int:
        """
        Eve measures a qubit in chosen basis
        
        Args:
            quantum_circuit: Alice's prepared quantum circuit
            eve_basis: 0 for Z basis, 1 for X basis
            
        Returns:
            Measurement result (0 or 1)
        """
        # Create measurement circuit
        qc = quantum_circuit.copy()
        qc.add_register(ClassicalRegister(1, 'c'))
        
        if eve_basis == 1:  # X basis measurement
            qc.h(0)
        
        qc.measure(0, 0)
        
        # Simulate measurement
        job = self.simulator.run(qc, shots=1)
        result = job.result()
        counts = result.get_counts()
        
        return int(list(counts.keys())[0])
    
    def _prepare_new_qubit(self, bit: int, basis: int, original_qubit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare new qubit that Eve sends to Bob after measurement
        
        Args:
            bit: Eve's measurement result
            basis: Basis used by Eve
            original_qubit_data: Original qubit data for reference
            
        Returns:
            New qubit data dictionary
        """
        # Create new quantum circuit for resent qubit
        qc = QuantumCircuit(1)
        
        if bit == 1:
            qc.x(0)  # Prepare |1⟩
        
        if basis == 1:  # X basis
            qc.h(0)  # Apply Hadamard
        
        # Create new qubit data
        new_qubit_data = {
            "index": original_qubit_data["index"],
            "alice_bit": original_qubit_data["alice_bit"],  # Original Alice's bit
            "alice_basis": original_qubit_data["alice_basis"],  # Original Alice's basis
            "quantum_circuit": qc,
            "state_vector": Statevector.from_instruction(qc),
            "eve_measured": True,
            "eve_bit": bit,
            "eve_basis": basis
        }
        
        return new_qubit_data
    
    def _apply_pauli_noise(self, qubit_data: Dict[str, Any], noise_type: str) -> Dict[str, Any]:
        """
        Apply Pauli noise to quantum circuit
        
        Args:
            qubit_data: Original qubit data
            noise_type: Type of Pauli operation ("X", "Y", "Z")
            
        Returns:
            Modified qubit data with noise applied
        """
        qc = qubit_data["quantum_circuit"].copy()
        
        if noise_type == "X":
            qc.x(0)  # Bit flip
        elif noise_type == "Y":
            qc.y(0)  # Bit and phase flip
        elif noise_type == "Z":
            qc.z(0)  # Phase flip
        
        # Create new qubit data with noise
        noisy_qubit_data = qubit_data.copy()
        noisy_qubit_data["quantum_circuit"] = qc
        noisy_qubit_data["state_vector"] = Statevector.from_instruction(qc)
        noisy_qubit_data["noise_applied"] = noise_type
        
        return noisy_qubit_data
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get statistics about attacks performed"""
        if not self.attack_log:
            return {"total_attacks": 0}
        
        stats = {
            "total_attacks": len(self.attack_log),
            "attack_types": {},
            "success_rate": 0.0
        }
        
        # Count attack types
        for attack in self.attack_log:
            attack_type = attack["attack_type"]
            if attack_type not in stats["attack_types"]:
                stats["attack_types"][attack_type] = 0
            stats["attack_types"][attack_type] += 1
        
        # Calculate success rate for intercept-resend attacks
        intercept_attacks = [a for a in self.attack_log if a["attack_type"] == "intercept_resend"]
        if intercept_attacks:
            successful = sum(1 for a in intercept_attacks if a.get("eve_basis") == a.get("alice_basis"))
            stats["success_rate"] = successful / len(intercept_attacks)
        
        return stats
    
    def clear_attack_log(self):
        """Clear the attack log"""
        self.attack_log.clear()
        logger.info("Eve attack log cleared")
    
    def get_attack_log(self) -> List[Dict[str, Any]]:
        """Get copy of attack log for analysis"""
        return self.attack_log.copy()