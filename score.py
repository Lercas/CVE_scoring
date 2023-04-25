import requests
import json

# после регистрации на nvd сюда ключик
NVD_API_KEY = 'your_nvd_api_key'

def get_cve_data(cve_id):
    url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}?apiKey={NVD_API_KEY}'
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.text)
        return data
    else:
        return None

# коэф (k) будет строиться в зависимости от важности объекта
def calculate_custom_score(cvss, exploitability, k=1):
    custom_score = (cvss * 100) + (exploitability * k)
    return custom_score

def main():
    cve_id = input("Введите номер уязвимости CVE: ")
    cve_data = get_cve_data(cve_id)

    if cve_data:
        cvss = cve_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
        print(f"CVSS: {cvss}")

        exploitability = float(input("Введите значение Exploitability (от 0 до 100): "))
        custom_score = calculate_custom_score(cvss, exploitability)

        print(f"Наш скоринг: {custom_score}")
    else:
        print("Не удалось получить информацию об уязвимости.")

if __name__ == '__main__':
    main()
