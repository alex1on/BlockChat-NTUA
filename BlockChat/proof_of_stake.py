# 1/04 A really basic logic of proof of stake just for testing

import random

def select_validator(validators):
    total_stakes = sum(validators.values())
    selection_points = [
        (validator, stake / total_stakes) for validator, stake in validators.items()
    ]
    random_point = random.random()
    current_point = 0
    for validator, stake_ratio in selection_points:
        current_point += stake_ratio
        if random_point <= current_point:
            return validator
