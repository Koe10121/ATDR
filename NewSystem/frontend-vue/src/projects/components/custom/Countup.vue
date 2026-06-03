<template>
  <div>
    <p class="font-weight-bold text-right"> ️ ผ่านไปแล้ว: {{ elapsedTime }} </p>
  </div>
</template>

<script>

import moment from 'moment';
export default {
  name: 'Countup',
  props: {
    start: { type: Date, required: true, default: Date.now }, // กำหนดเวลาต้นทาง
    name: { type: String, required: true }, // เช่น 'mfu-home'
    size: { type: String, default: 'md' }
  },
  data () {
    return {
      now: moment(),
      timer: null
    }
  },
  computed: {
    elapsedTime() {
      const duration = moment.duration(this.now.diff(this.start));
      const hours = Math.floor(duration.asHours());
      const minutes = duration.minutes();
      const seconds = duration.seconds();

      let parts = [];
      if (hours > 0) parts.push(`${hours} ชั่วโมง`);
      if (minutes > 0) parts.push(`${minutes} นาที`);
      parts.push(`${seconds} วินาที`);

      return parts.join(' ');
    }
  },
  mounted() {
    this.timer = setInterval(() => {
      this.now = moment();
    }, 1000);
  },
  beforeUnmount() {
    clearInterval(this.timer);
  }
}
</script>
