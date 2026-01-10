class Calculator {
  constructor() {
    this.display = document.getElementById('calc-display');
    this.history = [];
    this.setupEventListeners();
  }

  setupEventListeners() {
    document.querySelectorAll('.btn-number').forEach(btn => {
      btn.addEventListener('click', () => {
        this.appendToDisplay(btn.textContent);
      });
    });

    document.querySelectorAll('.btn-operator').forEach(btn => {
      btn.addEventListener('click', () => {
        this.appendToDisplay(btn.textContent);
      });
    });

    document.getElementById('btn-clear').addEventListener('click', () => {
      this.display.value = '';
    });

    document.getElementById('btn-equals').addEventListener('click', () => {
      try {
        const expression = this.display.value;
        const result = eval(expression);
        
        this.display.value = result;
        this.history.push(`${expression} = ${result}`);
        this.updateHistory();
      } catch (error) {
        this.display.value = 'Error';
      }
    });

    document.getElementById('btn-backspace').addEventListener('click', () => {
      this.display.value = this.display.value.slice(0, -1);
    });
  }

  appendToDisplay(value) {
    this.display.value += value;
  }

  updateHistory() {
    const historyEl = document.getElementById('calc-history');
    historyEl.innerHTML = this.history.slice(-5).reverse()
      .map(entry => `<div>${entry}</div>`)
      .join('');
  }
}
