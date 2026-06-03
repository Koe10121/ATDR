export default {
  mounted() {
    // attach once component is mounted
    this.$nextTick(() => this.attachInvalidClearHandlers());
  },
  updated() {
    // ensure any newly rendered required fields get listeners
    this.$nextTick(() => this.attachInvalidClearHandlers());
  },
  methods: {


    onCreate(){
      this.show = true;
    },
    onClose(){
      this.objs = {}
      this.show = false
    },


    preventCode(e){
      const allowedKeys = [
        'Backspace',
        'Delete',
        'ArrowLeft',
        'ArrowRight',
        'Tab',
        'Home',
        'End'
      ];

      // อนุญาตปุ่มควบคุม
      if (allowedKeys.includes(e.key)) return;

      // อนุญาตเฉพาะตัวเลข 0–9
      if (!/^[A-Za-z0-9_-]$/.test(e.key)) {
        e.preventDefault();
      }
    },
    preventNumber(e) {
      const allowedKeys = [
        'Backspace',
        'Delete',
        'ArrowLeft',
        'ArrowRight',
        'Tab',
        'Home',
        'End'
      ];

      // อนุญาตปุ่มควบคุม
      if (allowedKeys.includes(e.key)) return;

      // อนุญาตตัวเลข 0-9
      if (/^[0-9]$/.test(e.key)) return;

      // อนุญาตจุดทศนิยมได้แค่ 1 จุด
      if (e.key === '.') {
        if (e.target.value.includes('.')) {
          e.preventDefault(); // มีจุดแล้ว ห้ามพิมพ์ซ้ำ
        }
        return;
      }

      // นอกเหนือจากนี้ไม่อนุญาต
      e.preventDefault();
    },
    // Validate required labels and mark invalid elements
    validateRequired() {
      const container = this.$el;
      const labels = container.querySelectorAll('label.required');
      let valid = true;
      let firstInvalid = null;

      labels.forEach(label => {
        const wrap = label.parentElement;
        if (!wrap) return;

        // รองรับ vue-multiselect ก่อน
        const ms = wrap.querySelector('.multiselect');
        if (ms) {
          ms.classList.remove('is-invalid');
          const hasValue = !!ms.querySelector('.multiselect__single, .multiselect__tag');
          if (!hasValue) {
            ms.classList.add('is-invalid');
            valid = false;
            if (!firstInvalid) firstInvalid = ms;
          }
          return; // ข้ามไม่ต้องตรวจ input ภายใน multiselect
        }

        // พยายามหา input/select/textarea (กรณีทั่วไป)
        const input = wrap.querySelector('input, textarea, select');
        if (input) {
          input.classList.remove('is-invalid');
          const val = (input.value || '').toString().trim();
          if (!val) {
            input.classList.add('is-invalid');
            valid = false;
            if (!firstInvalid) firstInvalid = input;
          }
          return;
        }
      });

      if (!valid && firstInvalid && typeof firstInvalid.scrollIntoView === 'function') {
        firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      // Attach listeners to clear invalid as user fixes inputs
      this.$nextTick(() => this.attachInvalidClearHandlers());

      return valid;
    },

    // Attach listeners that clear is-invalid when values are entered/selected
    attachInvalidClearHandlers() {
      const container = this.$el;
      if (!container) return;

      const labels = container.querySelectorAll('label.required');
      labels.forEach(label => {
        const wrap = label.parentElement;
        if (!wrap) return;

        // Standard inputs/selects/textareas
        const input = wrap.querySelector('input, textarea, select');
        if (input && !input.dataset.invalidListener) {
          const handler = () => {
            const val = (input.value || '').toString().trim();
            if (val) input.classList.remove('is-invalid');
          };
          input.addEventListener('input', handler);
          input.addEventListener('change', handler);
          input.dataset.invalidListener = 'true';
        }

        // vue-multiselect: clear invalid when a selection exists
        const ms = wrap.querySelector('.multiselect');
        if (ms && !ms.dataset.invalidListener) {
          const check = () => {
            const hasValue = !!ms.querySelector('.multiselect__single, .multiselect__tag');
            if (hasValue) ms.classList.remove('is-invalid');
          };
          ms.addEventListener('click', check);
          ms.addEventListener('keyup', check);
          const msInput = ms.querySelector('input.multiselect__input');
          if (msInput) {
            msInput.addEventListener('input', check);
            msInput.addEventListener('change', check);
          }
          ms.dataset.invalidListener = 'true';
        }
      });
    }
  }
}
