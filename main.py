import tkinter as tk

from frames import IpFrame, MachineFrame

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Ark Server Controller")
    IpFrame(root)
    MachineFrame(root)
    root.mainloop()
