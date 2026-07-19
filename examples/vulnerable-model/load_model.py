# Loads the trained model at startup — do not run; this is a demo.
import torch
model = torch.load("model.pt")
print(model)
