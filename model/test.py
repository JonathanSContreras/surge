import os

xml_folder = "./10_10_162_0_24"
xml_list = sorted(f for f in os.listdir(xml_folder) if f.endswith(".xml"))
content = ""

for xml in xml_list:
    xml_path = os.path.join(xml_folder, xml)
    if os.path.isfile(xml_path):
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as file:
            data = file.read()
            content += data
            content += "\n<---- END OF XML CONTENT ---->\n"


with open(f"{xml_folder}/xml_content.txt", "w") as c:
    c.write(content)