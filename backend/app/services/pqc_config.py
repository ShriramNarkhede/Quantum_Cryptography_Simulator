"""
Post-Quantum Cryptography Configuration Service
Manages PQC algorithm selection and configuration
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PQCSecurityLevel(Enum):
    """NIST Post-Quantum Security Levels"""
    LEVEL_1 = "Level 1"  # 128-bit security
    LEVEL_2 = "Level 2"  # 128-bit security (alternative)
    LEVEL_3 = "Level 3"  # 192-bit security
    LEVEL_5 = "Level 5"  # 256-bit security


class PQCAlgorithmType(Enum):
    """Types of PQC algorithms"""
    KEM = "KEM"  # Key Encapsulation Mechanism
    SIGNATURE = "Signature"  # Digital Signature


@dataclass
class PQCAlgorithmConfig:
    """Configuration for a PQC algorithm"""
    name: str
    algorithm_type: PQCAlgorithmType
    security_level: PQCSecurityLevel
    public_key_size: int
    private_key_size: int
    ciphertext_size: Optional[int] = None  # For KEM
    signature_size: Optional[int] = None  # For signatures
    shared_secret_size: Optional[int] = None  # For KEM
    description: str = ""
    nist_standardized: bool = False
    available: bool = False


class PQCConfigService:
    """Service for managing PQC algorithm configuration"""
    
    def __init__(self):
        self.kyber_configs = self._initialize_kyber_configs()
        self.dilithium_configs = self._initialize_dilithium_configs()
        self.sphincs_configs = self._initialize_sphincs_configs()
    
    def _initialize_kyber_configs(self) -> Dict[str, PQCAlgorithmConfig]:
        """Initialize Kyber KEM configurations"""
        return {
            "Kyber512": PQCAlgorithmConfig(
                name="Kyber512",
                algorithm_type=PQCAlgorithmType.KEM,
                security_level=PQCSecurityLevel.LEVEL_1,
                public_key_size=800,
                private_key_size=1632,
                ciphertext_size=768,
                shared_secret_size=32,
                description="Kyber KEM with 128-bit security (NIST Level 1)",
                nist_standardized=True,
                available=True
            ),
            "Kyber768": PQCAlgorithmConfig(
                name="Kyber768",
                algorithm_type=PQCAlgorithmType.KEM,
                security_level=PQCSecurityLevel.LEVEL_3,
                public_key_size=1184,
                private_key_size=2400,
                ciphertext_size=1088,
                shared_secret_size=32,
                description="Kyber KEM with 192-bit security (NIST Level 3)",
                nist_standardized=True,
                available=False
            ),
            "Kyber1024": PQCAlgorithmConfig(
                name="Kyber1024",
                algorithm_type=PQCAlgorithmType.KEM,
                security_level=PQCSecurityLevel.LEVEL_5,
                public_key_size=1568,
                private_key_size=3168,
                ciphertext_size=1568,
                shared_secret_size=32,
                description="Kyber KEM with 256-bit security (NIST Level 5)",
                nist_standardized=True,
                available=False
            )
        }
    
    def _initialize_dilithium_configs(self) -> Dict[str, PQCAlgorithmConfig]:
        """Initialize Dilithium signature configurations"""
        return {
            "Dilithium2": PQCAlgorithmConfig(
                name="Dilithium2",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_2,
                public_key_size=1312,
                private_key_size=2528,
                signature_size=2420,
                description="Dilithium signature with 128-bit security (NIST Level 2)",
                nist_standardized=True,
                available=True
            ),
            "Dilithium3": PQCAlgorithmConfig(
                name="Dilithium3",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_3,
                public_key_size=1952,
                private_key_size=4000,
                signature_size=3309,
                description="Dilithium signature with 192-bit security (NIST Level 3)",
                nist_standardized=True,
                available=False
            ),
            "Dilithium5": PQCAlgorithmConfig(
                name="Dilithium5",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_5,
                public_key_size=2592,
                private_key_size=4864,
                signature_size=4595,
                description="Dilithium signature with 256-bit security (NIST Level 5)",
                nist_standardized=True,
                available=False
            )
        }
    
    def _initialize_sphincs_configs(self) -> Dict[str, PQCAlgorithmConfig]:
        """Initialize SPHINCS+ signature configurations"""
        return {
            "SPHINCS+-SHA256-128f-simple": PQCAlgorithmConfig(
                name="SPHINCS+-SHA256-128f-simple",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_1,
                public_key_size=32,
                private_key_size=64,
                signature_size=17088,
                description="SPHINCS+ stateless hash-based signature with 128-bit security (NIST Level 1)",
                nist_standardized=True,
                available=False
            ),
            "SPHINCS+-SHA256-192f-simple": PQCAlgorithmConfig(
                name="SPHINCS+-SHA256-192f-simple",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_3,
                public_key_size=48,
                private_key_size=96,
                signature_size=35664,
                description="SPHINCS+ stateless hash-based signature with 192-bit security (NIST Level 3)",
                nist_standardized=True,
                available=False
            ),
            "SPHINCS+-SHA256-256f-simple": PQCAlgorithmConfig(
                name="SPHINCS+-SHA256-256f-simple",
                algorithm_type=PQCAlgorithmType.SIGNATURE,
                security_level=PQCSecurityLevel.LEVEL_5,
                public_key_size=64,
                private_key_size=128,
                signature_size=49216,
                description="SPHINCS+ stateless hash-based signature with 256-bit security (NIST Level 5)",
                nist_standardized=True,
                available=False
            )
        }
    
    def get_algorithm_config(self, algorithm_name: str) -> Optional[PQCAlgorithmConfig]:
        """Get configuration for a specific algorithm"""
        # Check all algorithm dictionaries
        all_configs = {**self.kyber_configs, **self.dilithium_configs, **self.sphincs_configs}
        return all_configs.get(algorithm_name)
    
    def get_available_algorithms(self) -> Dict[str, List[PQCAlgorithmConfig]]:
        """Get all available PQC algorithms grouped by type"""
        return {
            "kem": [config for config in self.kyber_configs.values() if config.available],
            "signature": [
                config for config in {**self.dilithium_configs, **self.sphincs_configs}.values()
                if config.available
            ]
        }
    
    def get_all_algorithms(self) -> Dict[str, List[PQCAlgorithmConfig]]:
        """Get all PQC algorithms (available and unavailable) grouped by type"""
        return {
            "kem": list(self.kyber_configs.values()),
            "signature": list({**self.dilithium_configs, **self.sphincs_configs}.values())
        }
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of PQC configuration"""
        available = self.get_available_algorithms()
        all_algorithms = self.get_all_algorithms()
        
        return {
            "available_algorithms": {
                "kem_count": len(available["kem"]),
                "signature_count": len(available["signature"]),
                "kem": [{"name": a.name, "security_level": a.security_level.value} for a in available["kem"]],
                "signature": [{"name": a.name, "security_level": a.security_level.value} for a in available["signature"]]
            },
            "all_algorithms": {
                "kem_count": len(all_algorithms["kem"]),
                "signature_count": len(all_algorithms["signature"]),
                "kem": [{"name": a.name, "security_level": a.security_level.value, "available": a.available} 
                        for a in all_algorithms["kem"]],
                "signature": [{"name": a.name, "security_level": a.security_level.value, "available": a.available} 
                             for a in all_algorithms["signature"]]
            },
            "default_config": {
                "kem": "Kyber512",
                "signature": "Dilithium2"
            }
        }


# Global PQC configuration service instance
pqc_config_service = PQCConfigService()


