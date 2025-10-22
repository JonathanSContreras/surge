import os

xml_folder = "./10_10_162_0_24"
xml_list = (os.listdir(xml_folder))
content = ""

for xml in xml_list:
    print(xml)
    print(os.path.exists(f"{xml_folder}/{xml}"))
    with open(f"{xml_folder}/{xml}", "r", encoding="utf-8", errors="ignore") as f:
        content += f.read()

print(content)