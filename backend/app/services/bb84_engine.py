"""
BB84 Quantum Key Distribution Simulation Engine
Uses Qiskit for quantum circuit simulation
"""

import numpy as np
import random
import hashlib
import logging
from typing import List, Dict, Optional, AsyncGenerator, Any, Tuple
import asyncio
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
from qiskit.quantum_info import Statevector

logger = logging.getLogger(__name__)


class BB84Engine:
    """BB84 Protocol simulation engine"""
    
    def __init__(self, qber_threshold: float = 0.11):
        """
        Initialize BB84 engine
        
        Args:
            qber_threshold: QBER threshold above which Eve is detected
        """
        self.qber_threshold = qber_threshold
        self.simulator = AerSimulator()
        self.final_key: Optional[bytes] = None
        
        logger.info(f"BB84 Engine initialized with QBER threshold: {qber_threshold}")
    
    async def run_simulation(self, 
                           n_bits: int, 
                           test_fraction: float, 
                           eve_params: Optional[Dict[str, Any]] = None,
                           eve_module = None) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run complete BB84 simulation with progress updates
        
        Args:
            n_bits: Number of qubits to transmit
            test_fraction: Fraction of sifted key to use for QBER testing
            eve_params: Eve attack parameters if present
            eve_module: Eve module instance for attacks
        
        Yields:
            Progress updates with current simulation state
        """
        try:
            logger.info(f"Starting BB84 simulation: {n_bits} qubits, test_fraction={test_fraction}")
            
            # Step 1: Alice generates random bits and bases
            yield {"stage": "alice_preparation", "progress": 0.1, "message": "Alice preparing qubits..."}
            alice_bits, alice_bases = self._generate_alice_data(n_bits)
            await asyncio.sleep(0.1)  # Simulate processing time
            
            # Step 2: Alice prepares qubits
            yield {"stage": "qubit_preparation", "progress": 0.2, "message": "Preparing quantum states..."}
            qubits_data = self._prepare_qubits(alice_bits, alice_bases)
            await asyncio.sleep(0.2)
            
            # Step 3: Quantum transmission with optional Eve attacks
            yield {"stage": "transmission", "progress": 0.3, "message": "Transmitting qubits..."}
            
            if eve_module and eve_params:
                yield {"stage": "eve_attack", "progress": 0.35, "message": "Eve intercepting qubits..."}
                qubits_data = eve_module.apply_attack(qubits_data, eve_params)
                await asyncio.sleep(0.1)
            
            # Step 4: Bob generates random bases and measures
            yield {"stage": "bob_measurement", "progress": 0.5, "message": "Bob measuring qubits..."}
            bob_bases, bob_results = self._bob_measurement(qubits_data, n_bits)
            await asyncio.sleep(0.2)
            
            # Step 5: Sifting - compare bases publicly
            yield {"stage": "sifting", "progress": 0.6, "message": "Sifting keys..."}
            sifted_alice_bits, sifted_bob_bits, matching_indices = self._sifting(
                alice_bits, alice_bases, bob_bases, bob_results
            )
            
            yield {
                "stage": "sifted", 
                "progress": 0.65, 
                "message": f"Sifted key length: {len(sifted_alice_bits)} bits",
                "sifted_length": len(sifted_alice_bits),
                "original_length": n_bits
            }
            await asyncio.sleep(0.1)
            
            # Step 6: Test subset for QBER calculation
            yield {"stage": "qber_test", "progress": 0.7, "message": "Computing QBER..."}
            test_positions, qber = self._compute_qber(
                sifted_alice_bits, sifted_bob_bits, test_fraction
            )
            
            yield {
                "stage": "qber_computed",
                "progress": 0.75,
                "message": f"QBER: {qber:.3f}",
                "qber": qber,
                "threshold": self.qber_threshold,
                "test_bits_count": len(test_positions)
            }
            await asyncio.sleep(0.1)
            
            # Step 7: Check if QBER exceeds threshold (Eve detection)
            if qber > self.qber_threshold:
                yield {
                    "stage": "eve_detected",
                    "progress": 1.0,
                    "message": f"QBER ({qber:.3f}) exceeds threshold ({self.qber_threshold}). Eve detected!",
                    "qber": qber,
                    "threshold": self.qber_threshold,
                    "qber_exceeded": True,
                    "success": False
                }
                return
            
            # Step 8: Remove test bits from key
            yield {"stage": "key_distillation", "progress": 0.85, "message": "Removing test bits..."}
            raw_key_alice, raw_key_bob = self._remove_test_bits(
                sifted_alice_bits, sifted_bob_bits, test_positions
            )
            await asyncio.sleep(0.1)
            
            # Step 9: Privacy amplification (hash to final key)
            yield {"stage": "privacy_amplification", "progress": 0.9, "message": "Privacy amplification..."}
            final_key = self._privacy_amplification(raw_key_alice)
            self.final_key = final_key
            await asyncio.sleep(0.1)
            
            # Step 10: Simulation complete
            yield {
                "stage": "complete",
                "progress": 1.0,
                "message": f"BB84 complete! Final key: {len(final_key)} bytes",
                "qber": qber,
                "final_key_length": len(final_key),
                "success": True,
                "qber_exceeded": False
            }
            
            logger.info(f"BB84 simulation completed successfully. Final key length: {len(final_key)} bytes")
            
        except Exception as e:
            logger.error(f"Error in BB84 simulation: {str(e)}")
            yield {
                "stage": "error",
                "progress": 0.0,
                "message": f"Simulation error: {str(e)}",
                "success": False,
                "error": str(e)
            }
    
    def _generate_alice_data(self, n_bits: int) -> Tuple[List[int], List[int]]:
        """Generate Alice's random bits and bases"""
        alice_bits = [random.randint(0, 1) for _ in range(n_bits)]
        alice_bases = [random.randint(0, 1) for _ in range(n_bits)]  # 0=Z basis, 1=X basis
        return alice_bits, alice_bases
    
    def _prepare_qubits(self, alice_bits: List[int], alice_bases: List[int]) -> List[Dict[str, Any]]:
        """
        Prepare qubits according to Alice's bits and bases
        Returns list of qubit state information for transmission
        """
        qubits_data = []
        
        for i, (bit, basis) in enumerate(zip(alice_bits, alice_bases)):
            # Create quantum circuit for this qubit
            qc = QuantumCircuit(1)
            
            if bit == 1:
                qc.x(0)  # Prepare |1⟩ state
            
            if basis == 1:  # X basis
                qc.h(0)  # Apply Hadamard for +/- basis
            
            # Store qubit information
            qubit_info = {
                "index": i,
                "alice_bit": bit,
                "alice_basis": basis,
                "quantum_circuit": qc,
                "state_vector": Statevector.from_instruction(qc)
            }
            qubits_data.append(qubit_info)
        
        return qubits_data
    
    def _bob_measurement(self, qubits_data: List[Dict[str, Any]], n_bits: int) -> Tuple[List[int], List[int]]:
        """Bob randomly chooses measurement bases and measures qubits"""
        bob_bases = [random.randint(0, 1) for _ in range(n_bits)]
        bob_results = []
        
        for i, (qubit_data, bob_basis) in enumerate(zip(qubits_data, bob_bases)):
            # Create measurement circuit
            qc = qubit_data["quantum_circuit"].copy()
            qc.add_register(ClassicalRegister(1, 'c'))
            
            if bob_basis == 1:  # X basis measurement
                qc.h(0)
            
            qc.measure(0, 0)
            
            # Simulate measurement
            job = self.simulator.run(qc, shots=1)
            result = job.result()
            counts = result.get_counts()
            
            # Extract measurement result
            measured_bit = int(list(counts.keys())[0])
            bob_results.append(measured_bit)
        
        return bob_bases, bob_results
    
    def _sifting(self, alice_bits: List[int], alice_bases: List[int], 
                bob_bases: List[int], bob_results: List[int]) -> Tuple[List[int], List[int], List[int]]:
        """
        Sift keys by keeping only bits where Alice and Bob used same basis
        Returns sifted Alice bits, sifted Bob bits, and matching indices
        """
        sifted_alice = []
        sifted_bob = []
        matching_indices = []
        
        for i, (a_basis, b_basis) in enumerate(zip(alice_bases, bob_bases)):
            if a_basis == b_basis:  # Same basis used
                sifted_alice.append(alice_bits[i])
                sifted_bob.append(bob_results[i])
                matching_indices.append(i)
        
        return sifted_alice, sifted_bob, matching_indices
    
    def _compute_qber(self, alice_bits: List[int], bob_bits: List[int], 
                     test_fraction: float) -> Tuple[List[int], float]:
        """
        Compute QBER using a random subset of sifted bits
        Returns test bit positions and computed QBER
        """
        if len(alice_bits) == 0:
            return [], 1.0
        
        # Select random subset for testing
        n_test_bits = max(1, int(len(alice_bits) * test_fraction))
        test_positions = random.sample(range(len(alice_bits)), 
                                     min(n_test_bits, len(alice_bits)))
        
        # Compare test bits
        errors = 0
        for pos in test_positions:
            if alice_bits[pos] != bob_bits[pos]:
                errors += 1
        
        qber = errors / len(test_positions) if test_positions else 1.0
        return test_positions, qber
    
    def _remove_test_bits(self, alice_bits: List[int], bob_bits: List[int], 
                         test_positions: List[int]) -> Tuple[List[int], List[int]]:
        """Remove test bits from sifted key"""
        test_set = set(test_positions)
        
        raw_alice = [bit for i, bit in enumerate(alice_bits) if i not in test_set]
        raw_bob = [bit for i, bit in enumerate(bob_bits) if i not in test_set]
        
        return raw_alice, raw_bob
    
    def _privacy_amplification(self, key_bits: List[int]) -> bytes:
        """
        Apply privacy amplification using SHA-256
        Converts bit list to bytes and hashes to produce final key
        """
        # Convert bits to bytes
        bit_string = ''.join(map(str, key_bits))
        
        # Pad to byte boundary
        while len(bit_string) % 8 != 0:
            bit_string += '0'
        
        # Convert to bytes
        key_bytes = bytes([int(bit_string[i:i+8], 2) 
                          for i in range(0, len(bit_string), 8)])
        
        # Hash for privacy amplification
        final_key = hashlib.sha256(key_bytes).digest()
        
        return final_key
    
    def get_final_key(self) -> Optional[bytes]:
        """Get the final session key"""
        return self.final_key
    
    def clear_key(self):
        """Clear the stored final key"""
        self.final_key = None
    
    def get_theoretical_qber(self, eve_params: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate theoretical QBER for given Eve parameters
        Used for validation and testing
        """
        if not eve_params:
            return 0.0
        
        attack_type = eve_params.get("attack_type", "none")
        
        if attack_type == "intercept_resend":
            fraction = eve_params.get("params", {}).get("fraction", 0.0)
            return fraction * 0.25  # 25% error rate for full intercept-resend
        
        elif attack_type == "depolarizing":
            noise_prob = eve_params.get("params", {}).get("noise_probability", 0.0)
            return noise_prob / 2  # Depolarizing channel QBER approximation
        
        elif attack_type == "partial_intercept":
            fraction = eve_params.get("params", {}).get("fraction", 0.0)
            return fraction * 0.25
        
        return 0.0