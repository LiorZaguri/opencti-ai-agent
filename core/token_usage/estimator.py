import tiktoken
from typing import Dict, Any, Optional
from utils.logger import setup_logger

logger = setup_logger(name="token_usage", component_type="token_estimator")

class TokenEstimator:
    def __init__(self):
        self._encoders: Dict[str, Any] = {}

    def estimate(self, text: str, model: str = "gpt-3.5-turbo") -> int:
        """
        Estimates the number of tokens in a text string using tiktoken.
        Falls back to character-based estimation if tiktoken fails.
        
        Args:
            text: The text to estimate token count for
            model: The model to use for tokenization
            
        Returns:
            Estimated token count
        """
        if not isinstance(text, str):
            logger.warning(f"Invalid text type: {type(text)}")
            return 0

        if not text:  # Handle empty string case
            return 0

        try:
            # Get or create encoder for model
            if model not in self._encoders:
                self._encoders[model] = tiktoken.encoding_for_model(model)
            
            encoder = self._encoders[model]
            return len(encoder.encode(text))
            
        except Exception as e:
            logger.warning(f"Error estimating tokens with tiktoken: {e}. Using fallback method.")
            # Fallback: rough estimate based on characters
            return len(text) // 4  # Rough approximation

    def get_encoder(self, model: str) -> Optional[Any]:
        """Get tiktoken encoder for a specific model"""
        try:
            if model not in self._encoders:
                self._encoders[model] = tiktoken.encoding_for_model(model)
            return self._encoders[model]
        except Exception as e:
            logger.error(f"Failed to get encoder for model {model}: {e}")
            return None 